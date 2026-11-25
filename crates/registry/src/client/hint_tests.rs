// SPDX-License-Identifier: Apache-2.0
//! The cache of hints in the requests of a client: a hint saves the round
//! trips of the 401, and one that does not work is dropped, the registry is
//! asked again as without it and the user is told.

use super::*;
use crate::hints::{Auth, Hint};
use axum::extract::State;
use axum::http::{header, HeaderMap as AxHeaders, StatusCode as AxStatus};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The names the tests resolve themselves (`lookup`), and how many times
/// each was asked for.
static DNS: Mutex<Vec<(String, Vec<std::net::SocketAddr>, usize)>> = Mutex::new(Vec::new());

pub(crate) fn dns(name: &str) -> Option<Vec<std::net::SocketAddr>> {
    let mut names = DNS.lock().unwrap();
    let entry = names.iter_mut().find(|(n, _, _)| n == name)?;
    entry.2 += 1;
    Some(entry.1.clone())
}

/// What the requests of `client` found out for the cache of hints (the
/// scheme of the registry is for the pool, not the cache).
fn hint_notices(client: &RegistryClient) -> Notices {
    Notices {
        schemes: Vec::new(),
        ..client.take_notices()
    }
}

pub(super) fn name_resolves_to(name: &str, addrs: Vec<std::net::SocketAddr>) {
    DNS.lock().unwrap().push((name.into(), addrs, 0));
}

/// Names that a test says are public, so that it can be reached.
static PUBLIC: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub(super) fn say_public(name: &str) {
    PUBLIC.lock().unwrap().push(name.into());
}

pub(crate) fn pretend_public(name: &str) -> bool {
    PUBLIC.lock().unwrap().iter().any(|n| n == name)
}

fn asked_for(name: &str) -> usize {
    DNS.lock()
        .unwrap()
        .iter()
        .find(|(n, _, _)| n == name)
        .map_or(0, |e| e.2)
}

const BLOB: &[u8] = b"0123456789abcdef";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest() -> Digest {
    DIGEST.parse().unwrap()
}

#[derive(Default)]
struct Counts {
    ping: AtomicUsize,
    blob: AtomicUsize,
    token: AtomicUsize,
    stale: AtomicUsize,
    refused: AtomicUsize,
}

/// A registry on its own port that accepts the token `accept`, and whose
/// 401 sends clients to `realm`.
async fn registry(realm: String, accept: &'static str, basic: bool) -> (String, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let ok = move |h: &AxHeaders| match h.get(header::AUTHORIZATION) {
        Some(v) if basic => v.as_bytes().starts_with(b"Basic "),
        Some(v) => v.as_bytes() == format!("Bearer {accept}").as_bytes(),
        None => false,
    };
    let challenge = move || {
        if basic {
            "Basic realm=\"test\"".to_string()
        } else {
            format!("Bearer realm=\"{realm}\",service=\"test\"")
        }
    };
    let ping = {
        let challenge = challenge.clone();
        move |State(c): State<Arc<Counts>>, h: AxHeaders| async move {
            c.ping.fetch_add(1, Ordering::SeqCst);
            if ok(&h) {
                AxStatus::OK.into_response()
            } else {
                (
                    AxStatus::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, challenge())],
                )
                    .into_response()
            }
        }
    };
    let blob = move |State(c): State<Arc<Counts>>, h: AxHeaders| async move {
        c.blob.fetch_add(1, Ordering::SeqCst);
        if ok(&h) {
            BLOB.into_response()
        } else {
            (
                AxStatus::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge())],
            )
                .into_response()
        }
    };
    let app = Router::new()
        .route("/v2/", get(ping))
        .route(&format!("/v2/r/blobs/{DIGEST}"), get(blob))
        // its own token endpoints: the one a cached realm may name, one
        // that hands out a token the registry no longer takes, and one that
        // refuses
        .route(
            "/token",
            get(move |State(c): State<Arc<Counts>>| async move {
                c.token.fetch_add(1, Ordering::SeqCst);
                format!("{{\"token\":\"{accept}\",\"expires_in\":300}}")
            }),
        )
        .route(
            "/stale",
            get(|State(c): State<Arc<Counts>>| async move {
                c.stale.fetch_add(1, Ordering::SeqCst);
                r#"{"token":"stale","expires_in":300}"#
            }),
        )
        .route(
            "/refused",
            get(|State(c): State<Arc<Counts>>| async move {
                c.refused.fetch_add(1, Ordering::SeqCst);
                AxStatus::FORBIDDEN
            }),
        )
        .with_state(counts.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (host, counts)
}

/// A token endpoint on its own port (another host than the registry's) that
/// answers `status` and, when it is a success, the token `token`.
async fn auth_host(token: &'static str, status: AxStatus) -> (String, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let app = Router::new()
        .route(
            "/token",
            get(move |State(c): State<Arc<Counts>>| async move {
                c.token.fetch_add(1, Ordering::SeqCst);
                if status.is_success() {
                    format!("{{\"token\":\"{token}\",\"expires_in\":300}}").into_response()
                } else {
                    status.into_response()
                }
            }),
        )
        .with_state(counts.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (host, counts)
}

fn spec(host: &str, hint: Option<Hint>) -> EndpointSpec {
    EndpointSpec {
        host: host.to_string(),
        repository: "r".into(),
        insecure: true,
        allow_private: false,
        credentials: None,
        certs: Default::default(),
        brokered: false,
        hint,
        hints: true,
        min_speed: Default::default(),
        scheme: None,
    }
}

fn bearer(realm: String) -> Hint {
    Hint {
        transport: "http".into(),
        auth: Auth::Bearer {
            realm,
            service: Some("test".into()),
        },
        cdn: None,
    }
}

async fn get_blob(client: &RegistryClient, t: &Target) {
    let resp = client.get_blob(t, &digest(), None).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
}

fn client(spec: EndpointSpec) -> (RegistryClient, Target) {
    RegistryClient::from_specs(&[spec]).unwrap()
}

/// Requests to the registry, not counting the one that finds out whether
/// an insecure registry speaks HTTP.
fn requests(c: &Counts) -> usize {
    c.ping.load(Ordering::SeqCst) - 1 + c.blob.load(Ordering::SeqCst)
}

#[tokio::test]
async fn without_a_hint_the_first_request_is_refused_and_asked_again() {
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    let (host, c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(&host, None));
    get_blob(&client, &t).await;
    assert_eq!(requests(&c), 2, "the 401 and the request again");
    assert_eq!(auth_counts.token.load(Ordering::SeqCst), 1);
    let notices = hint_notices(&client);
    assert!(notices.warnings.is_empty());
    assert_eq!(
        notices.hints,
        vec![Note::Auth {
            registry: host.clone(),
            transport: "http".into(),
            auth: Auth::Bearer {
                realm: format!("http://{auth}/token"),
                service: Some("test".into())
            }
        }],
        "what the 401 said is for the cache"
    );
}

#[tokio::test]
async fn a_hint_goes_straight_to_the_token_endpoint_of_the_registry() {
    let (host, c) = registry("http://unused.invalid/token".into(), "good", false).await;
    let (client, t) = client(spec(&host, Some(bearer(format!("http://{host}/token")))));
    get_blob(&client, &t).await;
    get_blob(&client, &t).await;
    assert_eq!(
        c.blob.load(Ordering::SeqCst),
        2,
        "one request for each blob, no 401"
    );
    // the connection made while the token came is on its own: wait for it
    // (it is always made) rather than take whatever count there is now
    tokio::time::timeout(Duration::from_secs(5), async {
        while c.ping.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the connection to the registry was not made");
    assert_eq!(
        c.ping.load(Ordering::SeqCst),
        2,
        "the scheme, and the connection made while the token came"
    );
    assert_eq!(c.token.load(Ordering::SeqCst), 1);
    assert!(
        hint_notices(&client).is_empty(),
        "nothing is said when the hint works"
    );
}

#[tokio::test]
async fn a_hint_whose_token_endpoint_is_gone_is_dropped_and_the_user_told() {
    let (auth, _) = auth_host("good", AxStatus::OK).await;
    let (host, c) = registry(format!("http://{auth}/token"), "good", false).await;
    // nothing is served there
    let stale = format!("http://{host}/gone");
    let (client, t) = client(spec(&host, Some(bearer(stale))));
    get_blob(&client, &t).await;
    let notices = hint_notices(&client);
    assert_eq!(notices.warnings.len(), 1, "{notices:?}");
    assert!(notices.warnings[0].contains(&host), "{notices:?}");
    assert!(notices.warnings[0].contains("404"), "{notices:?}");
    assert_eq!(notices.hints.len(), 2);
    assert_eq!(
        notices.hints[0],
        Note::Forget {
            registry: host.clone()
        }
    );
    assert!(matches!(
        &notices.hints[1],
        Note::Auth { auth: Auth::Bearer { realm, .. }, .. } if *realm == format!("http://{auth}/token")
    ));
    assert!(c.blob.load(Ordering::SeqCst) >= 1);
    // the registry's own answer is used from now on: no more words
    get_blob(&client, &t).await;
    assert!(hint_notices(&client).is_empty());
}

#[tokio::test]
async fn a_token_endpoint_that_refuses_the_hint_is_asked_about_again() {
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    let (host, c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(&host, Some(bearer(format!("http://{host}/refused")))));
    get_blob(&client, &t).await;
    assert_eq!(c.refused.load(Ordering::SeqCst), 1);
    assert_eq!(auth_counts.token.load(Ordering::SeqCst), 1);
    let notices = hint_notices(&client);
    assert_eq!(notices.warnings.len(), 1);
    assert!(notices.warnings[0].contains("403"), "{notices:?}");
}

#[tokio::test]
async fn a_token_the_registry_rejects_drops_the_hint_and_the_request_goes_again_without_a_token() {
    // the realm of the hint hands out tokens, but not the ones the registry
    // takes any more (the registry changed its challenge)
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    let (host, c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(&host, Some(bearer(format!("http://{host}/stale")))));
    get_blob(&client, &t).await;
    assert_eq!(c.stale.load(Ordering::SeqCst), 1);
    assert_eq!(auth_counts.token.load(Ordering::SeqCst), 1);
    // the request with the stale token, the one without a token that says
    // what the registry wants, and the one with the new token
    assert_eq!(c.blob.load(Ordering::SeqCst), 3);
    let notices = hint_notices(&client);
    assert_eq!(notices.warnings.len(), 1, "{notices:?}");
    assert!(notices.warnings[0].contains("401"), "{notices:?}");
    assert!(notices
        .hints
        .iter()
        .any(|n| matches!(n, Note::Auth { auth: Auth::Bearer { realm, .. }, .. } if *realm == format!("http://{auth}/token"))));
}

#[tokio::test]
async fn a_hint_that_was_served_is_not_blamed_for_a_later_401() {
    let (host, _c) = registry("http://unused.invalid/token".into(), "good", false).await;
    let (client, t) = client(spec(&host, Some(bearer(format!("http://{host}/token")))));
    get_blob(&client, &t).await;
    assert!(!client.drop_hint(&t.endpoint.host, "an expired token"));
    assert!(hint_notices(&client).is_empty());
}

#[tokio::test]
async fn a_basic_registry_with_credentials_goes_straight_to_the_request() {
    let (host, c) = registry(String::new(), "", true).await;
    let mut s = spec(
        &host,
        Some(Hint {
            transport: "http".into(),
            auth: Auth::Basic,
            cdn: None,
        }),
    );
    s.credentials = Some(Credentials {
        username: "u".into(),
        password: "p".into(),
        ..Default::default()
    });
    let (client, t) = client(s);
    get_blob(&client, &t).await;
    assert_eq!(requests(&c), 1);
    assert!(hint_notices(&client).is_empty());
}

#[tokio::test]
async fn a_basic_registry_without_a_hint_learns_it() {
    let (host, c) = registry(String::new(), "", true).await;
    let mut s = spec(&host, None);
    s.credentials = Some(Credentials {
        username: "u".into(),
        password: "p".into(),
        ..Default::default()
    });
    let (client, t) = client(s);
    get_blob(&client, &t).await;
    assert!(requests(&c) >= 1);
    assert!(hint_notices(&client).hints.iter().any(|n| matches!(
        n,
        Note::Auth {
            auth: Auth::Basic,
            ..
        }
    )));
}

#[test]
fn a_hint_is_held_to_what_a_live_realm_is() {
    let seeded = |s: EndpointSpec| {
        let (client, _) = client(s);
        let seeded = client
            .challenges
            .lock()
            .unwrap()
            .contains_key("registry.example");
        seeded
    };
    let mut s = spec(
        "registry.example",
        Some(bearer("https://auth.example/token".into())),
    );
    s.insecure = false;
    s.hint.as_mut().unwrap().transport = "https".into();
    // a cached realm is for the credentials only on the registry's own
    // host, whether or not the client has any: they are looked up when
    // the token is asked for
    assert!(
        !seeded(s.clone()),
        "an anonymous pull takes no realm of another host"
    );
    s.credentials = Some(Credentials::default());
    assert!(
        !seeded(s.clone()),
        "another host never gets the credentials"
    );
    let mut anonymous = s.clone();
    anonymous.credentials = None;
    anonymous.repository = "other".into();
    assert!(!seeded(anonymous.clone()));
    s.hint = Some(bearer("https://registry.example/token".into()));
    s.hint.as_mut().unwrap().transport = "https".into();
    assert!(seeded(s.clone()));
    // plain HTTP only for a registry that is insecure
    s.credentials = None;
    s.hint = Some(bearer("http://registry.example/token".into()));
    assert!(!seeded(s.clone()), "not sound: http realm for https");
    s.hint.as_mut().unwrap().transport = "http".into();
    assert!(
        !seeded(s.clone()),
        "http hint for a registry that is not insecure"
    );
    s.insecure = true;
    assert!(seeded(s.clone()));
    // a hint that says nothing, or is not a hint
    s.hint = Some(bearer("not a url".into()));
    assert!(!seeded(s.clone()));
    s.hint = Some(Hint {
        transport: "http".into(),
        auth: Auth::None,
        cdn: Some("cdn.example".into()),
    });
    assert!(!seeded(s.clone()));
    // a broker answers for a brokered endpoint: nothing to take
    s.hint = Some(bearer("http://registry.example/token".into()));
    s.brokered = true;
    assert!(!seeded(s));
}

#[test]
fn local_hosts_are_told_apart() {
    for h in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.10",
        "172.16.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "[::1]",
        "[fd00::1]",
        "[fe80::1]",
        "[::ffff:127.0.0.1]",
        "localhost",
        "LOCALHOST.",
        "a.localhost",
    ] {
        assert!(local_host(h), "{h}");
    }
    for h in [
        "8.8.8.8",
        "[2001:4860::8888]",
        "cdn01.quay.io",
        "localhost.example",
    ] {
        assert!(!local_host(h), "{h}");
    }
}

#[test]
fn what_is_shown_of_a_reason_is_one_short_line() {
    assert_eq!(brief("a\nb\u{1b}[31mc"), "a b [31mc");
    assert_eq!(brief(&"x".repeat(500)).len(), 120);
}

#[tokio::test]
async fn a_worker_that_does_not_report_keeps_quiet() {
    let (auth, _) = auth_host("good", AxStatus::OK).await;
    let (host, _c) = registry(format!("http://{auth}/token"), "good", false).await;
    let mut s = spec(&host, None);
    s.hints = false;
    let (client, t) = client(s);
    get_blob(&client, &t).await;
    assert!(hint_notices(&client).is_empty());
}

/// A listener that counts the connections it is made, and drops them.
async fn counting_listener() -> (String, Arc<AtomicUsize>) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    (host, accepted)
}

async fn connected(accepted: &AtomicUsize) -> usize {
    // (the listener counts a connection as it accepts it: let it)
    tokio::task::yield_now().await;
    accepted.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_cdn_is_connected_to_in_advance_once_for_each_ask() {
    let (host, _c) = registry(String::new(), "", false).await;
    let (cdn, accepted) = counting_listener().await;
    let (client, t) = client(spec(&host, None));
    let url = format!("http://{cdn}/");
    futures::future::join_all((0..4).map(|_| client.preconnect(&t, Some(&url)))).await;
    assert_eq!(connected(&accepted).await, 4);
}

#[tokio::test]
async fn nothing_is_connected_to_that_a_registry_could_not_be_sent_to() {
    let (cdn, accepted) = counting_listener().await;
    let mut s = spec("registry.example", None);
    s.insecure = false;
    let (client, t) = client(s);
    // plain HTTP from a registry reached over HTTPS, an address with a user,
    // something that is not an address, nothing
    for url in [
        Some(format!("http://{cdn}/")),
        // (a host of this machine, for a registry that is not on it)
        Some(format!("https://{cdn}/")),
        Some(format!(
            "https://localhost:{}/",
            cdn.rsplit(':').next().unwrap()
        )),
        Some(format!("https://user@{cdn}/")),
        Some("not a url".to_string()),
        Some("ftp://example.org/".to_string()),
        None,
    ] {
        client.preconnect(&t, url.as_deref()).await;
    }
    assert_eq!(connected(&accepted).await, 0);
}

/// Connect in advance to a CDN in a process whose proxy is `proxy`, with
/// `no_proxy` in `NO_PROXY`: the connections the CDN and the proxy saw.
fn preconnect_with_proxy(no_proxy: Option<&str>) -> (usize, usize) {
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        // child-only
        std::env::remove_var(var);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (cdn, direct) = counting_listener().await;
            let (proxy, proxied) = counting_listener().await;
            // child-only
            std::env::set_var("HTTP_PROXY", format!("http://{proxy}"));
            if let Some(no_proxy) = no_proxy {
                // child-only
                std::env::set_var("NO_PROXY", no_proxy);
            }
            // (an insecure registry may be sent to plain HTTP; one on this
            // machine to a CDN on it)
            let mut s = spec("127.0.0.1:9", None);
            s.insecure = true;
            let (client, t) = RegistryClient::from_specs(&[s]).unwrap();
            let before = proxied.load(Ordering::SeqCst);
            client.preconnect(&t, Some(&format!("http://{cdn}/"))).await;
            (
                direct.load(Ordering::SeqCst),
                proxied.load(Ordering::SeqCst) - before,
            )
        })
}

#[test]
fn a_connection_in_advance_goes_through_the_proxy() {
    velarx_base::testing::in_child(|| {
        let (direct, proxied) = preconnect_with_proxy(None);
        assert_eq!(direct, 0, "the CDN was not asked directly");
        assert!(proxied >= 1, "the proxy was");
    });
}

#[test]
fn a_connection_in_advance_respects_no_proxy() {
    velarx_base::testing::in_child(|| {
        let (direct, _) = preconnect_with_proxy(Some("127.0.0.1"));
        assert_eq!(direct, 1, "the CDN is not behind the proxy");
    });
}

#[tokio::test]
async fn what_v2_says_is_no_hint_for_a_pull_without_credentials() {
    // (the warm-up of a worker asks `/v2/`, which says to take a token; a
    // registry that serves the manifests of public images without one is
    // not to be sent for a token the next time)
    let (auth, _) = auth_host("good", AxStatus::OK).await;
    let (host, _c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(&host, None));
    client.warm(&t).await.unwrap();
    assert!(hint_notices(&client).is_empty());
}

/// A name with this port, as a listener on 127.0.0.1 is reached by it.
fn port_of(host: &str) -> u16 {
    host.rsplit(':').next().unwrap().parse().unwrap()
}

#[tokio::test]
async fn a_name_that_resolves_to_a_private_address_is_not_connected_to_in_advance() {
    let (cdn, accepted) = counting_listener().await;
    let port = port_of(&cdn);
    let local: std::net::SocketAddr = cdn.parse().unwrap();
    let public: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();
    for (name, addrs) in [
        ("loop.dns.test", vec![local]),
        ("private.dns.test", vec!["10.1.2.3:1".parse().unwrap()]),
        (
            "linklocal.dns.test",
            vec!["169.254.169.254:1".parse().unwrap()],
        ),
        ("ula.dns.test", vec!["[fd00::1]:1".parse().unwrap()]),
        (
            "mapped.dns.test",
            vec!["[::ffff:127.0.0.1]:1".parse().unwrap()],
        ),
        // one address that is public does not make the others fine
        ("mixed.dns.test", vec![public, local]),
        ("none.dns.test", vec![]),
    ] {
        name_resolves_to(name, addrs);
        let mut s = spec("registry.example", None);
        s.insecure = false;
        let (client, t) = client(s);
        client
            .preconnect(&t, Some(&format!("https://{name}:{port}/")))
            .await;
        assert_eq!(asked_for(name), 1, "{name} was resolved");
    }
    assert_eq!(connected(&accepted).await, 0);
}

#[tokio::test]
async fn a_name_is_resolved_once_and_the_connection_goes_to_what_was_checked() {
    // (the name is in no DNS: the connection can only find the address that
    // the check had, and the system is not asked again)
    let (cdn, accepted) = counting_listener().await;
    name_resolves_to("pinned.dns.test", vec![cdn.parse().unwrap()]);
    PUBLIC.lock().unwrap().push("pinned.dns.test".into());
    let mut s = spec("registry.example", None);
    s.insecure = false;
    let (client, t) = client(s);
    let url = format!("https://pinned.dns.test:{}/", port_of(&cdn));
    client.preconnect(&t, Some(&url)).await;
    assert_eq!(connected(&accepted).await, 1);
    assert_eq!(asked_for("pinned.dns.test"), 1);
    assert_eq!(
        client.host(&t).unwrap().pinned_names(),
        0,
        "the pin ends with the connection"
    );
}

#[tokio::test]
async fn a_checked_name_is_connected_to_at_the_address_that_was_checked() {
    // the pinned address is the one the connection goes to even where the
    // system's resolver would say another: a host that is not resolvable at
    // all is reached
    let (cdn, accepted) = counting_listener().await;
    let addr: std::net::SocketAddr = cdn.parse().unwrap();
    let (host, _c) = registry(String::new(), "", false).await;
    let (client, t) = client(spec(&host, None));
    let host_transport = client.host(&t).unwrap();
    let _pin = host_transport.pin("elsewhere.dns.test", vec![addr]);
    let url = format!("http://elsewhere.dns.test:{}/", addr.port());
    // (the registry is local, so `preconnect` does not resolve: this is
    // the connection of the client itself)
    client.preconnect(&t, Some(&url)).await;
    drop(_pin);
    assert_eq!(connected(&accepted).await, 1);
}

#[tokio::test]
async fn the_token_does_not_wait_for_the_connection_to_the_registry() {
    use tokio::sync::Notify;
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    // a registry that answers the scheme probe and holds the `HEAD /v2/`
    let app = Router::new().route(
        "/token",
        get(|| async { r#"{"token":"good","expires_in":300}"# }),
    );
    let app = app.route(
        "/v2/",
        get(|| async { AxStatus::OK }).head({
            let (arrived, release) = (arrived.clone(), release.clone());
            move || {
                let (arrived, release) = (arrived.clone(), release.clone());
                async move {
                    arrived.notify_one();
                    release.notified().await;
                    AxStatus::OK
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (client, t) = client(spec(&host, Some(bearer(format!("http://{host}/token")))));
    // (a guard, not a wait: the token is there at once)
    let header = tokio::time::timeout(
        Duration::from_secs(2),
        client.authorization(&t, "pull", false),
    )
    .await
    .expect("the token waited for the connection to the registry")
    .unwrap();
    assert_eq!(header.unwrap().to_str().unwrap(), "Bearer good");
    // the connection is still made, on its own
    arrived.notified().await;
    release.notify_one();
}

#[tokio::test]
async fn the_redirect_reported_is_the_one_of_the_endpoint_that_served_the_blob() {
    // the first endpoint sends the blob to a CDN that does not have it, the
    // second sends it to another that does
    let (cdn_bad, _) = start_cdn(AxStatus::NOT_FOUND).await;
    let (cdn_ok, _) = start_cdn(AxStatus::OK).await;
    let first = redirecting_registry(&cdn_bad).await;
    let second = redirecting_registry(&cdn_ok).await;
    let (client, t) =
        RegistryClient::from_specs(&[spec(&first, None), spec(&second, None)]).unwrap();
    get_blob(&client, &t).await;
    let (index, url) = client.redirect_of(&t, &digest()).unwrap();
    assert_eq!(index, 1, "the second endpoint served it");
    assert!(url.starts_with(&format!("http://{cdn_ok}/")), "{url}");
    // and when the first serves it, the second's old redirect is not told
    let (cdn_good, _) = start_cdn(AxStatus::OK).await;
    let first = redirecting_registry(&cdn_good).await;
    let (client, t) =
        RegistryClient::from_specs(&[spec(&first, None), spec(&second, None)]).unwrap();
    client.redirects.put(
        &t.fallbacks[0].blob_key(&digest()),
        "http://stale.example/b",
    );
    get_blob(&client, &t).await;
    let (index, url) = client.redirect_of(&t, &digest()).unwrap();
    assert_eq!(index, 0);
    assert!(url.starts_with(&format!("http://{cdn_good}/")), "{url}");
}

/// A server of blobs for a registry to send clients to: it answers `status`.
async fn start_cdn(status: AxStatus) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let app = Router::new().route(
        "/blob",
        get(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                if status.is_success() {
                    BLOB.into_response()
                } else {
                    status.into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (host, hits)
}

/// A registry with no authentication that sends every blob to `cdn`.
async fn redirecting_registry(cdn: &str) -> String {
    let location = format!("http://{cdn}/blob");
    let app = Router::new()
        .route("/v2/", get(|| async { AxStatus::OK }))
        .route(
            &format!("/v2/r/blobs/{DIGEST}"),
            get(move || {
                let location = location.clone();
                async move { (AxStatus::TEMPORARY_REDIRECT, [(header::LOCATION, location)]) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    host
}

/// `name` for the registry at `host` (a loopback address), a name that is
/// public as far as the policy knows: `name:port`.
fn public_name(host: &str, name: &str) -> String {
    name_resolves_to(name, vec![host.parse().unwrap()]);
    PUBLIC.lock().unwrap().push(name.into());
    format!("{name}:{}", port_of(host))
}

async fn blob_error(client: &RegistryClient, t: &Target) -> String {
    match client.get_blob(t, &digest(), None).await {
        Ok(_) => panic!("the blob was served"),
        Err(e) => e.to_string(),
    }
}

#[tokio::test]
async fn a_realm_on_a_private_address_is_refused_for_a_public_registry() {
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    let (host, _c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(
        &public_name(&host, "realm-literal.registry.test"),
        None,
    ));
    let e = blob_error(&client, &t).await;
    assert!(e.contains("refusing"), "{e}");
    assert_eq!(auth_counts.token.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_realm_that_resolves_to_a_private_address_is_refused() {
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    name_resolves_to("rebind.auth.test", vec![auth.parse().unwrap()]);
    let realm = format!("http://rebind.auth.test:{}/token", port_of(&auth));
    let (host, _c) = registry(realm, "good", false).await;
    let (client, t) = client(spec(
        &public_name(&host, "realm-rebind.registry.test"),
        None,
    ));
    let e = blob_error(&client, &t).await;
    assert!(
        e.contains("refusing") || e.contains("error sending request"),
        "{e}"
    );
    assert_eq!(
        auth_counts.token.load(Ordering::SeqCst),
        0,
        "no connection was made to the private address"
    );
}

#[tokio::test]
async fn a_redirect_to_a_private_address_is_refused_for_a_public_registry() {
    let (cdn, hits) = start_cdn(AxStatus::OK).await;
    let host = redirecting_registry(&cdn).await;
    let (client, t) = client(spec(&public_name(&host, "redirect.registry.test"), None));
    let e = blob_error(&client, &t).await;
    assert!(e.contains("refusing"), "{e}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_refused_redirect_is_not_used_by_the_next_request() {
    let (cdn, hits) = start_cdn(AxStatus::OK).await;
    let host = redirecting_registry(&cdn).await;
    let (client, t) = client(spec(&public_name(&host, "cached.registry.test"), None));
    let e = blob_error(&client, &t).await;
    assert!(e.contains("refusing"), "{e}");
    let e = blob_error(&client, &t).await;
    assert!(e.contains("refusing"), "{e}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// `name:port` for the registry at `host` (a loopback address), a name
/// that resolves to `host` and to `others`, with no word that it is public.
fn name_of_addresses(host: &str, name: &str, others: &[&str]) -> String {
    let port = port_of(host);
    let mut addrs: Vec<std::net::SocketAddr> = vec![host.parse().unwrap()];
    for a in others {
        addrs.push(format!("{a}:{port}").parse().unwrap());
    }
    name_resolves_to(name, addrs);
    format!("{name}:{port}")
}

#[tokio::test]
async fn a_registry_that_has_a_public_address_among_private_ones_is_public() {
    let (auth, auth_counts) = auth_host("good", AxStatus::OK).await;
    let (host, _c) = registry(format!("http://{auth}/token"), "good", false).await;
    let name = name_of_addresses(&host, "mixed.registry.test", &["10.9.8.7"]);
    say_public("mixed.registry.test");
    let (client, t) = client(spec(&name, None));
    let e = blob_error(&client, &t).await;
    assert!(e.contains("refusing"), "{e}");
    assert_eq!(auth_counts.token.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_registry_that_has_private_addresses_only_may_send_the_client_there() {
    let (cdn, hits) = start_cdn(AxStatus::OK).await;
    let host = redirecting_registry(&cdn).await;
    let name = name_of_addresses(&host, "private.registry.test", &["10.9.8.7"]);
    let (client, t) = client(spec(&name, None));
    get_blob(&client, &t).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_hinted_registry_on_private_addresses_only_takes_its_private_realm() {
    // (with the scheme known and a hint, the token is asked for before any
    // connection to the registry, at a realm that is the registry's own
    // name: nothing is known of the name yet)
    let (host, c) = registry("http://unused.invalid/token".into(), "good", false).await;
    let name = name_of_addresses(&host, "hinted.private.test", &[]);
    let mut s = spec(&name, Some(bearer(format!("http://{name}/token"))));
    s.scheme = Some(crate::target::Scheme::Http);
    let (client, t) = client(s);
    get_blob(&client, &t).await;
    assert_eq!(c.token.load(Ordering::SeqCst), 1);
    assert!(hint_notices(&client).is_empty(), "the hint was not dropped");
}

#[tokio::test]
async fn a_registry_on_a_private_address_may_send_the_client_there() {
    let (cdn, hits) = start_cdn(AxStatus::OK).await;
    let host = redirecting_registry(&cdn).await;
    let (client, t) = client(spec(&host, None));
    get_blob(&client, &t).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_setting_of_the_registry_allows_private_addresses() {
    let (cdn, hits) = start_cdn(AxStatus::OK).await;
    let host = redirecting_registry(&cdn).await;
    let mut s = spec(&public_name(&host, "allowed.registry.test"), None);
    s.allow_private = true;
    let (client, t) = client(s);
    get_blob(&client, &t).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_token_request_does_not_echo_the_answer() {
    let app = Router::new().route(
        "/token",
        get(|| async { (AxStatus::INTERNAL_SERVER_ERROR, "SECRET-INTERNAL-DATA") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (host, _c) = registry(format!("http://{auth}/token"), "good", false).await;
    let (client, t) = client(spec(&host, None));
    let e = blob_error(&client, &t).await;
    assert!(e.contains("500"), "{e}");
    assert!(!e.contains("SECRET-INTERNAL-DATA"), "{e}");
}

#[tokio::test]
async fn a_registry_that_refuses_the_credentials_of_a_login_is_unauthorized() {
    let (auth, _) = auth_host("good", AxStatus::UNAUTHORIZED).await;
    let (host, _) = registry(format!("http://{auth}/token"), "good", false).await;
    let mut s = spec(&host, None);
    s.credentials = Some(Credentials {
        username: "u".into(),
        password: "wrong".into(),
        ..Default::default()
    });
    let (client, t) = client(s);
    let e = client.check_login(&t).await.unwrap_err();
    assert!(matches!(e, ImageError::Unauthorized(_)), "{e}");
    assert!(e.to_string().ends_with("invalid username/password"), "{e}");
}

const HUB: &str = "registry-1.docker.io";

/// Docker Hub has no realm of its own in the program: its token endpoint
/// is another host than the registry, so what a cache says of it is not
/// taken, and the registry is asked for it.
#[test]
fn docker_hub_has_no_built_in_realm_and_its_cached_one_is_another_host() {
    for credentials in [false, true] {
        let mut s = spec(HUB, None);
        s.insecure = false;
        if credentials {
            s.credentials = Some(Credentials::default());
        }
        let (fresh, _) = client(s.clone());
        assert!(
            fresh.challenges.lock().unwrap().get(HUB).is_none(),
            "nothing is known before the first request"
        );
        s.hint = Some(Hint {
            transport: "https".into(),
            auth: bearer("https://auth.docker.io/token".into()).auth,
            cdn: None,
        });
        let (cached, _) = client(s);
        assert!(
            cached.challenges.lock().unwrap().get(HUB).is_none(),
            "the realm of another host is learned live"
        );
    }
}

#[test]
fn a_hint_that_does_not_work_is_forgotten_with_a_word() {
    // the cache of the user is not so quiet
    let mut s = spec(
        "registry.example",
        Some(bearer("https://registry.example/token".into())),
    );
    s.insecure = false;
    s.hint.as_mut().unwrap().transport = "https".into();
    let (client, _) = self::client(s);
    assert!(client.drop_hint("registry.example", "token endpoint: 404"));
    assert_eq!(hint_notices(&client).warnings.len(), 1);
}
