// SPDX-License-Identifier: Apache-2.0
//! Authentication to a registry with a token service: credentials scoped
//! to a repository, OAuth2 refresh tokens (identity tokens) and registry
//! tokens, against an in-process registry.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use velarx_registry::client::RegistryClient;
use velarx_registry::target::TransportConfig;
use velarx_registry::{AuthConfig, Credentials, RegistriesConfig};
use velarx_types::ImageReference;

const MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#;

#[derive(Default)]
struct Tokens {
    /// How the tokens were asked: "GET user" or "POST refresh".
    log: Mutex<Vec<String>>,
}

async fn token_get(
    State(t): State<Arc<Tokens>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let user = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .map(|b| String::from_utf8(base64_decode(b)).unwrap_or_default())
        .unwrap_or_default();
    t.log.lock().unwrap().push(format!(
        "GET {user} {}",
        q.get("scope").cloned().unwrap_or_default()
    ));
    if user == "alice:secret" {
        return json(serde_json::json!({"token": "basic-token"}));
    }
    StatusCode::UNAUTHORIZED.into_response()
}

fn json(v: serde_json::Value) -> Response {
    ([("content-type", "application/json")], v.to_string()).into_response()
}

async fn token_post(State(t): State<Arc<Tokens>>, body: String) -> Response {
    let f: HashMap<String, String> = reqwest::Url::parse(&format!("http://x/?{body}"))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let refresh = f.get("refresh_token").cloned().unwrap_or_default();
    t.log.lock().unwrap().push(format!(
        "POST {} {} {refresh}",
        f.get("grant_type").cloned().unwrap_or_default(),
        f.get("scope").cloned().unwrap_or_default()
    ));
    if refresh == "refresh-me" {
        return json(serde_json::json!({"access_token": "oauth-token"}));
    }
    StatusCode::UNAUTHORIZED.into_response()
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

async fn start() -> (String, Arc<Tokens>) {
    let tokens = Arc::new(Tokens::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let realm = format!("http://{host}/token");
    let accepted = ["basic-token", "oauth-token", "registry-token"];
    let challenge = move || {
        (
            StatusCode::UNAUTHORIZED,
            [(
                "www-authenticate",
                format!(r#"Bearer realm="{realm}",service="test""#),
            )],
        )
            .into_response()
    };
    let c2 = challenge.clone();
    let app = Router::new()
        .route("/v2/", get(move || async move { challenge() }))
        .route(
            "/v2/:a/:b/manifests/:r",
            get(move |headers: HeaderMap| async move {
                let ok = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .is_some_and(|t| accepted.contains(&t));
                if !ok {
                    return c2();
                }
                (
                    [("content-type", "application/vnd.oci.image.manifest.v1+json")],
                    MANIFEST,
                )
                    .into_response()
            }),
        )
        .route("/token", get(token_get).post(token_post))
        .with_state(tokens.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (host, tokens)
}

fn client(host: &str, auth: AuthConfig) -> RegistryClient {
    RegistryClient::with_config(
        TransportConfig {
            registries: RegistriesConfig::parse(&format!(
                "[[registry]]\nlocation = \"{host}\"\ninsecure = true\n"
            ))
            .unwrap(),
            certs_dirs: vec![],
            tls_verify: true,
        },
        auth,
    )
}

async fn fetch(c: &RegistryClient, host: &str, repo: &str) -> bool {
    let r = ImageReference::parse(&format!("{host}/{repo}:latest")).unwrap();
    c.get_manifest(&r).await.is_ok()
}

#[tokio::test]
async fn credentials_are_scoped_to_their_repository() {
    let (host, tokens) = start().await;
    let auth = AuthConfig::from_credentials([
        (
            format!("{host}/org").as_str(),
            Credentials::basic("alice", "secret"),
        ),
        (host.as_str(), Credentials::basic("bob", "wrong")),
    ]);
    let c = client(&host, auth);
    assert!(fetch(&c, &host, "org/img").await);
    assert!(!fetch(&c, &host, "other/img").await);
    let log = tokens.log.lock().unwrap().clone();
    assert_eq!(log[0], "GET alice:secret repository:org/img:pull");
    assert!(log[1].starts_with("GET bob:wrong repository:other/img"));
}

#[tokio::test]
async fn an_identity_token_is_exchanged_by_post() {
    let (host, tokens) = start().await;
    let auth = AuthConfig::from_credentials([(
        host.as_str(),
        Credentials {
            identity_token: Some("refresh-me".into()),
            ..Default::default()
        },
    )]);
    let c = client(&host, auth);
    assert!(fetch(&c, &host, "org/img").await);
    let log = tokens.log.lock().unwrap().clone();
    assert_eq!(
        log,
        ["POST refresh_token repository:org/img:pull refresh-me"]
    );
}

#[tokio::test]
async fn a_registry_token_is_sent_as_it_is() {
    let (host, tokens) = start().await;
    let auth = AuthConfig::from_credentials([(
        host.as_str(),
        Credentials {
            registry_token: Some("registry-token".into()),
            ..Default::default()
        },
    )]);
    let c = client(&host, auth);
    assert!(fetch(&c, &host, "org/img").await);
    assert!(tokens.log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_auth_file_is_read_with_its_scopes() {
    let (host, _tokens) = start().await;
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("auth.json");
    velarx_registry::auth::store_credentials(
        Some(&path),
        &format!("{host}/org"),
        "alice",
        "secret",
    )
    .unwrap();
    let c = client(&host, AuthConfig::load_file(&path));
    assert!(fetch(&c, &host, "org/img").await);
    assert!(!fetch(&c, &host, "else/img").await);
    std::fs::write(&path, "{broken").unwrap();
    let c = client(&host, AuthConfig::load_file(&path));
    assert!(!fetch(&c, &host, "org/img").await);
}

#[tokio::test]
async fn the_access_of_a_request_comes_first() {
    let (host, tokens) = start().await;
    let c = client(&host, AuthConfig::default());
    assert!(!fetch(&c, &host, "org/img").await);
    let access = velarx_registry::auth::RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    };
    let with = c.with_access(&access);
    assert!(fetch(&with, &host, "org/img").await);
    // the client it came from is unchanged, and its tokens are not shared
    assert!(!fetch(&c, &host, "org/img").await);
    assert!(tokens
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("GET alice:secret")));
}
