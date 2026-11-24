// SPDX-License-Identifier: Apache-2.0
//! Tests of what the client does today with credentials, mirrors and the
//! answers of a registry that are not what a well-behaved one gives.  A
//! test whose comment starts with "Pins a problem:" holds a behaviour that
//! is not the one a reader would expect; the comment says what that is.

use super::*;
use axum::body::Bytes as AxBytes;
use axum::http::{header, HeaderMap as AxHeaders, Uri};
use axum::Router;

const MANIFEST: &[u8] = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#;
const BLOB: &[u8] = b"0123456789abcdef";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest() -> Digest {
    DIGEST.parse().unwrap()
}

/// A request a fake server got.
#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    auth: Option<String>,
    body: usize,
}

/// What a fake server answers.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn ok(body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            ..Self::status(200)
        }
    }

    fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn redirect(status: u16, to: &str) -> Self {
        Self::status(status).with("Location", to)
    }

    fn challenge(www_authenticate: &str) -> Self {
        Self::status(401).with("WWW-Authenticate", www_authenticate)
    }

    fn bearer_challenge(realm: &str) -> Self {
        Self::challenge(&format!("Bearer realm=\"{realm}\",service=\"test\""))
    }

    fn basic_challenge() -> Self {
        Self::challenge("Basic realm=\"test\"")
    }

    fn token() -> Self {
        Self::ok(br#"{"token":"T","expires_in":300}"#)
    }

    fn into_axum(self) -> axum::response::Response {
        let mut b = axum::response::Response::builder().status(self.status);
        for (name, value) in self.headers {
            b = b.header(name, value);
        }
        b.body(axum::body::Body::from(self.body)).unwrap()
    }
}

/// What the fake servers got, with the name of each.
type Seen = Arc<Mutex<Vec<(&'static str, Req)>>>;

/// The requests of `server`, as `METHOD path auth`, with ` body=N` for a
/// request that has a body.
fn got(seen: &Seen, server: &str) -> Vec<String> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(s, _)| *s == server)
        .map(|(_, r)| {
            let body = if r.body > 0 {
                format!(" body={}", r.body)
            } else {
                String::new()
            };
            format!(
                "{} {} {}{body}",
                r.method,
                r.path,
                r.auth.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

/// The requests of `server` for a path that starts with `prefix`.
fn got_under(seen: &Seen, server: &str, prefix: &str) -> Vec<String> {
    let want = format!(" {prefix}");
    got(seen, server)
        .into_iter()
        .filter(|l| l.contains(&want))
        .collect()
}

/// What `server` was asked for a manifest (not the probe of its scheme).
fn manifests(seen: &Seen, server: &str) -> Vec<String> {
    got_under(seen, server, "/v2/r/manifests/")
}

fn path_of(req: &Req) -> &str {
    req.path.split('?').next().unwrap()
}

/// A listener on a loopback port, and its `host:port`: a server that
/// names another needs the name of that one first.
async fn listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    (listener, host)
}

/// A plain HTTP server on `listener` that answers every request with
/// `handler` (the request, and the server's own `host:port`) and notes it.
fn serve_on<F>(
    (listener, host): (tokio::net::TcpListener, String),
    name: &'static str,
    seen: &Seen,
    handler: F,
) -> String
where
    F: Fn(&Req, &str) -> Reply + Clone + Send + Sync + 'static,
{
    let (seen, own) = (seen.clone(), host.clone());
    let app = Router::new().fallback(
        move |m: axum::http::Method, uri: Uri, h: AxHeaders, body: AxBytes| {
            let (seen, own, handler) = (seen.clone(), own.clone(), handler.clone());
            async move {
                let req = Req {
                    method: m.to_string(),
                    path: uri
                        .path_and_query()
                        .map(|p| p.to_string())
                        .unwrap_or_default(),
                    auth: h
                        .get(header::AUTHORIZATION)
                        .map(|v| v.to_str().unwrap().to_string()),
                    body: body.len(),
                };
                let answer = handler(&req, &own);
                seen.lock().unwrap().push((name, req));
                answer.into_axum()
            }
        },
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    host
}

async fn serve<F>(name: &'static str, seen: &Seen, handler: F) -> String
where
    F: Fn(&Req, &str) -> Reply + Clone + Send + Sync + 'static,
{
    serve_on(listener().await, name, seen, handler)
}

/// A self-signed certificate for 127.0.0.1 and a TLS acceptor for it.
struct Cert {
    pem: String,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
}

fn cert() -> Cert {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "127.0.0.1").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(1_000_000_000).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(3).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let x509 = b.build();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&x509).unwrap();
    Cert {
        pem: String::from_utf8(x509.to_pem().unwrap()).unwrap(),
        acceptor: Arc::new(acceptor.build()),
    }
}

/// An HTTPS server (HTTP/1.1, one request for each connection) with the
/// certificate `cert` on `listener` that answers like [`serve_on`].
fn serve_tls<F>(
    (listener, host): (std::net::TcpListener, String),
    name: &'static str,
    seen: &Seen,
    cert: &Cert,
    handler: F,
) -> String
where
    F: Fn(&Req, &str) -> Reply + Clone + Send + Sync + 'static,
{
    use std::io::{BufRead, Read, Write};
    let (seen, own, acceptor) = (seen.clone(), host.clone(), cert.acceptor.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, own, acceptor, handler) =
                (seen.clone(), own.clone(), acceptor.clone(), handler.clone());
            std::thread::spawn(move || {
                // a client that does not trust the certificate ends here
                let Ok(stream) = acceptor.accept(stream) else {
                    return;
                };
                let mut stream = std::io::BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let (method, path) = (
                    parts.next().unwrap().to_string(),
                    parts.next().unwrap().to_string(),
                );
                let (mut auth, mut length) = (None, 0);
                loop {
                    line.clear();
                    stream.read_line(&mut line).unwrap();
                    let Some((k, v)) = line.trim_end().split_once(':') else {
                        break;
                    };
                    match k.to_ascii_lowercase().as_str() {
                        "authorization" => auth = Some(v.trim().to_string()),
                        "content-length" => length = v.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let req = Req {
                    method,
                    path,
                    auth,
                    body: length,
                };
                let answer = handler(&req, &own);
                seen.lock().unwrap().push((name, req));
                let mut out = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    answer.status,
                    answer.body.len()
                );
                for (k, v) in &answer.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                let stream = stream.get_mut();
                let _ = stream.write_all(out.as_bytes());
                let _ = stream.write_all(&answer.body);
                let _ = stream.shutdown();
            });
        }
    });
    host
}

/// A client for a configuration text, `tls_verify` as given, trusting
/// each certificate of `cas` for its host as `certs.d` would, with these
/// credentials.  The directory of the certificates is the second value.
fn client_of(
    conf: &str,
    tls_verify: bool,
    cas: &[(&str, &Cert)],
    credentials: &[(&str, Credentials)],
) -> (RegistryClient, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for (host, cert) in cas {
        let d = dir.path().join(host);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("ca.crt"), &cert.pem).unwrap();
    }
    let mut auth = AuthConfig::default();
    for (host, c) in credentials {
        auth = auth.with_credentials(host, c.clone());
    }
    let client = RegistryClient::with_config(
        TransportConfig {
            registries: super::super::config::RegistriesConfig::parse(conf).unwrap(),
            certs_dirs: vec![dir.path().to_path_buf()],
            tls_verify,
        },
        auth,
    );
    (client, dir)
}

/// `insecure` blocks for these hosts.
fn insecure(hosts: &[&str]) -> String {
    hosts
        .iter()
        .map(|h| format!("[[registry]]\nprefix = \"{h}\"\ninsecure = true\n"))
        .collect()
}

fn basic_of(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

fn user() -> Credentials {
    Credentials::basic("u", "pw")
}

fn reference(host: &str) -> ImageReference {
    ImageReference::parse(&format!("{host}/r:latest")).unwrap()
}

/// A registry that asks for a Bearer token from `realm` (its own `/token`
/// when `realm` is none), gives `answer` (the manifest for 200) for what
/// is asked with it, and gives a token on `/token`.
async fn token_registry(
    name: &'static str,
    seen: &Seen,
    realm: Option<String>,
    answer: u16,
) -> String {
    serve(name, seen, move |req, own| {
        let realm = realm.as_deref().unwrap_or(own);
        match path_of(req) {
            "/token" => Reply::token(),
            "/v2/" if req.auth.is_some() => Reply::status(200),
            _ if req.auth.as_deref() == Some("Bearer T") => match answer {
                200 => Reply::ok(MANIFEST),
                other => Reply::status(other),
            },
            _ => Reply::bearer_challenge(&format!("http://{realm}/token")),
        }
    })
    .await
}

/// The credentials given for one pull (`--creds`) go to the host that was
/// named and to the token endpoint it names, not to a mirror on another
/// host, nor to the token endpoint of that mirror.
#[tokio::test]
async fn creds_of_the_command_line_go_to_the_host_named_and_not_to_a_mirror_elsewhere() {
    let seen = Seen::default();
    let mirror_realm = serve("mirror-realm", &seen, |_, _| Reply::token()).await;
    let mirror = token_registry("mirror", &seen, Some(mirror_realm), 404).await;
    let primary = token_registry("primary", &seen, None, 200).await;
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n\
         [[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let client = client_of(&conf, true, &[], &[])
        .0
        .with_access(&crate::auth::RegistryAccess {
            creds: Some(Credentials::basic("u", "pw")),
            ..Default::default()
        });
    client
        .get_manifest_raw(&reference(&primary), None)
        .await
        .unwrap();
    let basic = basic_of("u", "pw");
    let token = format!("GET /token?service=test&scope=repository%3Ar%3Apull {basic}");
    // the realm of the mirror, on a host of its choice, got no password
    // (its token request had none)
    assert!(got(&seen, "mirror-realm")
        .iter()
        .all(|l| !l.contains("Basic")));
    assert_eq!(got_under(&seen, "primary", "/token"), [token]);
    // and the mirror itself got only a bearer token
    assert!(got(&seen, "mirror").iter().all(|l| !l.contains("Basic")));
}

/// A digest-only mirror is asked for `name:tag@sha512:D` by the digest, never
/// by the tag, which does not name what the digest does: a mirror that
/// answers with other bytes is refused, and the next endpoint is tried.
#[tokio::test]
async fn a_digest_only_mirror_is_asked_by_the_digest_and_a_mismatch_tries_the_next() {
    let seen = Seen::default();
    let wrong = serve("mirror", &seen, |_, _| Reply::ok(b"not the manifest")).await;
    let primary = serve("primary", &seen, |_, _| Reply::ok(MANIFEST)).await;
    let conf = |mirror: &str| {
        format!(
            "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n\
             [[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n\
             pull-from-mirror = \"digest-only\"\n"
        )
    };
    let d = Digest::of(Algorithm::Sha512, MANIFEST);
    let by_tag = ImageReference::parse(&format!("{primary}/r:latest@{d}")).unwrap();
    let (_, digest, _) = client_of(&conf(&wrong), true, &[], &[])
        .0
        .get_manifest_raw(&by_tag, None)
        .await
        .unwrap();
    // the mirror was asked by the digest and its bytes were refused; the
    // registry, which is not asked by a digest, was asked the tag
    assert_eq!(digest, d);
    assert_eq!(
        manifests(&seen, "mirror"),
        [format!("GET /v2/r/manifests/{d} -")]
    );
    assert_eq!(
        manifests(&seen, "primary"),
        ["GET /v2/r/manifests/latest -"]
    );
    // a mirror with the right bytes serves them to the digest, no other way
    let right = serve("mirror2", &seen, |_, _| Reply::ok(MANIFEST)).await;
    let (_, digest, _) = client_of(&conf(&right), true, &[], &[])
        .0
        .get_manifest_raw(&by_tag, None)
        .await
        .unwrap();
    assert_eq!(digest, d);
    assert_eq!(
        manifests(&seen, "mirror2"),
        [format!("GET /v2/r/manifests/{d} -")]
    );
    // a sha256 digest drops the tag: the mirror is asked by the digest
    let d256 = Digest::of(Algorithm::Sha256, MANIFEST);
    let by_digest = ImageReference::parse(&format!("{primary}/r:latest@{d256}")).unwrap();
    client_of(&conf(&right), true, &[], &[])
        .0
        .get_manifest_raw(&by_digest, None)
        .await
        .unwrap();
    assert_eq!(
        manifests(&seen, "mirror2")[1],
        format!("GET /v2/r/manifests/{d256} -")
    );
    // and a reference without a digest does not ask it at all
    client_of(&conf(&right), true, &[], &[])
        .0
        .get_manifest_raw(&reference(&primary), None)
        .await
        .unwrap();
    assert_eq!(manifests(&seen, "mirror2").len(), 2);
    assert_eq!(
        manifests(&seen, "primary"),
        [
            "GET /v2/r/manifests/latest -",
            "GET /v2/r/manifests/latest -"
        ]
    );
}

/// A registry (not TLS) that wants the credentials `u`:`pw` for
/// everything and gives `answer` to what is asked with them.
async fn gated(
    name: &'static str,
    seen: &Seen,
    listener: (tokio::net::TcpListener, String),
    answer: impl Fn(&Req) -> Reply + Clone + Send + Sync + 'static,
) -> String {
    serve_on(listener, name, seen, move |req, _| {
        if req.auth.as_deref() == Some(&basic_of("u", "pw")) {
            if path_of(req) == "/v2/" {
                return Reply::status(200);
            }
            answer(req)
        } else {
            Reply::basic_challenge()
        }
    })
}

/// An https registry that answers the start of an upload with a
/// `Location` over plain HTTP: the pieces of the layer are not sent there.
#[tokio::test]
async fn an_http_upload_location_of_an_https_registry_gets_nothing() {
    let seen = Seen::default();
    let plain = serve("plain", &seen, |_, _| Reply::status(201)).await;
    let cert = cert();
    let (l, home) = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = l.local_addr().unwrap().to_string();
        (l, host)
    };
    let location = format!("http://{plain}/up/1");
    serve_tls(
        (l, home.clone()),
        "home",
        &seen,
        &cert,
        move |req, _| match req.auth.as_deref() {
            Some(a) if a == basic_of("u", "pw") => {
                Reply::status(202).with("Location", location.clone())
            }
            _ => Reply::basic_challenge(),
        },
    );
    let (client, _dir) = client_of("", true, &[(&home, &cert)], &[(&home, user())]);
    let t = client.push_target(&reference(&home)).unwrap();
    let UploadStart::Session(session) = client.start_upload(&t, None).await.unwrap() else {
        panic!("no session")
    };
    assert_eq!(session.as_str(), format!("http://{plain}/up/1"));
    let err = client
        .finish_upload(&t, &session, 0, &digest(), Bytes::from_static(BLOB))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("gave an http:// location"),
        "{err}"
    );
    assert!(err.to_string().contains("relativeurls"), "{err}");
    assert!(got(&seen, "plain").is_empty());
    // the registry's own requests had the credentials
    assert!(got(&seen, "home")
        .iter()
        .any(|l| l.starts_with("POST /v2/r/blobs/uploads/ Basic")));
}

/// An https registry behind a proxy that does not pass the scheme answers
/// the start of an upload with its own address over http: that is the
/// registry, and the pieces go to it over https, with the credentials.
#[tokio::test]
async fn an_http_upload_location_of_the_https_registry_itself_is_asked_over_https() {
    let seen = Seen::default();
    let cert = cert();
    let (l, home) = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = l.local_addr().unwrap().to_string();
        (l, host)
    };
    let location = format!("http://{home}/up/1");
    serve_tls(
        (l, home.clone()),
        "home",
        &seen,
        &cert,
        move |req, _| match (req.auth.as_deref(), req.method.as_str()) {
            (Some(a), "POST") if a == basic_of("u", "pw") => {
                Reply::status(202).with("Location", location.clone())
            }
            (Some(a), "PATCH") if a == basic_of("u", "pw") => {
                Reply::status(202).with("Location", location.clone())
            }
            (Some(a), "PUT") if a == basic_of("u", "pw") => Reply::status(201),
            _ => Reply::basic_challenge(),
        },
    );
    let (client, _dir) = client_of("", true, &[(&home, &cert)], &[(&home, user())]);
    let t = client.push_target(&reference(&home)).unwrap();
    let UploadStart::Session(session) = client.start_upload(&t, None).await.unwrap() else {
        panic!("no session")
    };
    client
        .finish_upload(&t, &session, 0, &digest(), Bytes::from_static(BLOB))
        .await
        .unwrap();
    assert!(got(&seen, "home")
        .iter()
        .any(|l| l.starts_with("PUT /up/1?digest=") && l.contains(&basic_of("u", "pw"))));
}

/// A registry that sends a blob to a CDN (another origin), which sends it
/// back to the registry: the path on the way back is the CDN's choice, and
/// has no `Authorization`.
#[tokio::test]
async fn a_chain_through_a_cdn_back_to_the_registry_has_no_authorization() {
    let seen = Seen::default();
    let (cdn_l, home_l) = (listener().await, listener().await);
    let (cdn, home) = (cdn_l.1.clone(), home_l.1.clone());
    let back = format!("http://{home}/v2/anything/chosen/by/the/cdn");
    serve_on(cdn_l, "cdn", &seen, move |_, _| Reply::redirect(302, &back));
    let to_cdn = format!("http://{cdn}/hop");
    gated("home", &seen, home_l, move |req| {
        if path_of(req) == format!("/v2/r/blobs/{DIGEST}") {
            Reply::redirect(302, &to_cdn)
        } else {
            Reply::ok(b"what only the credentials open")
        }
    })
    .await;
    let (client, _dir) = client_of(&insecure(&[&home]), true, &[], &[(&home, user())]);
    let t = client.target(&reference(&home)).unwrap();
    let resp = client.get_blob(&t, &digest(), None).await.unwrap();
    // the registry does not open for a request that has no credentials
    assert_eq!(resp.status(), 401);
    // the CDN, another origin, was given nothing
    assert_eq!(got(&seen, "cdn"), ["GET /hop -"]);
    assert_eq!(
        got_under(&seen, "home", "/v2/anything"),
        ["GET /v2/anything/chosen/by/the/cdn -"]
    );
}

/// An upload `Location` on another host gets the piece, without the
/// credentials; the `Location` that host answers with is read against that
/// host, so that it cannot choose a path of the registry, which would get a
/// piece and the credentials.
#[tokio::test]
async fn an_upload_host_of_another_origin_does_not_pick_a_path_of_the_registry() {
    let seen = Seen::default();
    let (other_l, home_l) = (listener().await, listener().await);
    let (other, home) = (other_l.1.clone(), home_l.1.clone());
    serve_on(other_l, "other", &seen, |_, _| {
        Reply::status(202).with("Location", "/v2/some-other-repo/blobs/uploads/picked")
    });
    let session = format!("http://{other}/up/1");
    gated("home", &seen, home_l, move |req| {
        match req.method.as_str() {
            "POST" => Reply::status(202).with("Location", session.clone()),
            _ => Reply::status(202).with("Location", "/v2/r/blobs/uploads/next"),
        }
    })
    .await;
    let (client, _dir) = client_of(&insecure(&[&home]), true, &[], &[(&home, user())]);
    let t = client.push_target(&reference(&home)).unwrap();
    let UploadStart::Session(session) = client.start_upload(&t, None).await.unwrap() else {
        panic!("no session")
    };
    let next = client
        .upload_chunk(&t, &session, 0, Bytes::from_static(BLOB))
        .await
        .unwrap();
    // the other host got the piece, no credentials
    assert_eq!(got(&seen, "other"), ["PATCH /up/1 - body=16"]);
    assert_eq!(
        next.as_str(),
        format!("http://{other}/v2/some-other-repo/blobs/uploads/picked")
    );
    client
        .upload_chunk(&t, &next, 16, Bytes::from_static(BLOB))
        .await
        .unwrap();
    // the next piece went to that host again, and the registry got none
    assert_eq!(
        got_under(&seen, "other", "/v2/some-other-repo"),
        ["PATCH /v2/some-other-repo/blobs/uploads/picked - body=16"]
    );
    assert!(got_under(&seen, "home", "/v2/some-other-repo").is_empty());
}

/// The pull of a blob from an HTTPS registry that asks for a token at
/// `https://realm/token` (its own when `realm_on_home`) and sends the blob
/// to `https://cdn/blob`: three servers, three certificates; the registry's
/// is the only one trusted when `secure`.  The blob or the error, and what
/// the servers saw.
async fn https_pull(secure: bool, realm_on_home: bool) -> (ImageResult<Vec<u8>>, Seen) {
    let seen = Seen::default();
    let (c_home, c_realm, c_cdn) = (cert(), cert(), cert());
    let tls = || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = l.local_addr().unwrap().to_string();
        (l, host)
    };
    let (home_l, realm_l, cdn_l) = (tls(), tls(), tls());
    let (home, realm, cdn) = (home_l.1.clone(), realm_l.1.clone(), cdn_l.1.clone());
    let token_at = format!(
        "https://{}/token",
        if realm_on_home { &home } else { &realm }
    );
    let blob_at = format!("https://{cdn}/blob");
    serve_tls(realm_l, "realm", &seen, &c_realm, |_, _| Reply::token());
    serve_tls(cdn_l, "cdn", &seen, &c_cdn, |_, _| Reply::ok(BLOB));
    serve_tls(
        home_l,
        "home",
        &seen,
        &c_home,
        move |req, _| match path_of(req) {
            "/token" => Reply::token(),
            _ if req.auth.as_deref() == Some("Bearer T") => Reply::redirect(302, &blob_at),
            _ => Reply::bearer_challenge(&token_at),
        },
    );
    let conf = if secure {
        String::new()
    } else {
        insecure(&[&home])
    };
    let (client, _dir) = client_of(&conf, secure, &[(&home, &c_home)], &[]);
    let t = client.target(&reference(&home)).unwrap();
    let result = match client.get_blob(&t, &digest(), None).await {
        Ok(resp) if resp.status().is_success() => Ok(resp.bytes().await.unwrap().to_vec()),
        Ok(resp) => Err(ImageError::Registry(resp.status().to_string())),
        Err(e) => Err(e),
    };
    (result, seen)
}

/// `insecure` on a registry covers the certificates of the token endpoint
/// and of the CDN it names, on other hosts, with other certificates; the
/// same pull of a registry that is not insecure, which trusts the
/// registry's certificate only, fails at each.
#[tokio::test]
async fn an_insecure_registry_covers_the_certificates_of_its_realm_and_its_cdn() {
    let (blob, seen) = https_pull(false, false).await;
    assert_eq!(blob.unwrap(), BLOB);
    assert_eq!(got(&seen, "realm").len(), 1);
    assert_eq!(got(&seen, "cdn"), ["GET /blob -"]);
    // the controls: with the registry's certificate only trusted, a realm
    // with another certificate is not reached, nor a CDN
    let (blob, seen) = https_pull(true, false).await;
    assert!(blob.is_err());
    assert!(got(&seen, "realm").is_empty());
    let (blob, seen) = https_pull(true, true).await;
    assert!(blob.is_err());
    assert_eq!(got_under(&seen, "home", "/token").len(), 1);
    assert!(got(&seen, "cdn").is_empty());
}

/// A registry that wants `u`:`pw` and sends every blob to `cdn`.
async fn redirecting(name: &'static str, seen: &Seen, cdn: &str) -> String {
    let to = format!("http://{cdn}/blob");
    gated(name, seen, listener().await, move |_| {
        Reply::redirect(302, &to)
    })
    .await
}

/// The redirect a registry gave to one caller (with its credentials) is
/// kept under `host/repository@digest` for that caller: another caller of
/// the same client (with other credentials, even wrong ones) has the
/// registry asked.  Another registry or another repository, with the same
/// digest, is not served from it either.
#[tokio::test]
async fn a_redirect_learned_with_the_credentials_of_a_caller_does_not_serve_another() {
    let seen = Seen::default();
    let cdn_a = serve("cdn-a", &seen, |_, _| Reply::ok(BLOB)).await;
    let cdn_b = serve("cdn-b", &seen, |_, _| Reply::ok(BLOB)).await;
    let a = redirecting("a", &seen, &cdn_a).await;
    let b = redirecting("b", &seen, &cdn_b).await;
    let base = client_of(&insecure(&[&a, &b]), true, &[], &[]).0;
    let access = |user: &str, password: &str| crate::auth::RegistryAccess {
        creds: Some(Credentials::basic(user, password)),
        ..Default::default()
    };
    let alice = base.with_access(&access("u", "pw"));
    let mallory = base.with_access(&access("m", "guess"));
    let status = |client: &RegistryClient, host: &str, repository: &str| {
        let client = client.clone();
        let r = ImageReference::parse(&format!("{host}/{repository}:latest")).unwrap();
        async move {
            let t = client.target(&r).unwrap();
            let resp = client.get_blob(&t, &digest(), None).await.unwrap();
            resp.status().as_u16()
        }
    };
    let asked = |server| got_under(&seen, server, "/v2/r/blobs/").len();
    // without the entry the registry refuses the caller
    assert_eq!(status(&mallory, &a, "r").await, 401);
    assert_eq!(status(&alice, &a, "r").await, 200);
    let hits = asked("a");
    // the same caller is sent to the CDN without the registry being asked
    assert_eq!(status(&alice, &a, "r").await, 200);
    assert_eq!(asked("a"), hits);
    assert_eq!(got(&seen, "cdn-a").len(), 2);
    // another caller has the registry asked, and is refused
    assert_eq!(status(&mallory, &a, "r").await, 401);
    assert!(asked("a") > hits);
    assert_eq!(got(&seen, "cdn-a").len(), 2);
    // the key has the registry and the repository: others are asked
    assert_eq!(status(&alice, &b, "r").await, 200);
    assert_eq!(asked("b"), 1);
    assert_eq!(got(&seen, "cdn-a").len(), 2);
    assert_eq!(got(&seen, "cdn-b").len(), 1);
    assert_eq!(status(&alice, &a, "s").await, 200);
    assert_eq!(got_under(&seen, "a", "/v2/s/blobs/").len(), 1);
    assert_eq!(got(&seen, "cdn-a").len(), 3);
}

/// Redirects that never end stop after ten of them (eleven requests), and
/// a registry that asks for a token for ever is asked for the thing three
/// times, with two tokens.
#[tokio::test]
async fn rounds_of_redirects_and_of_challenges_are_bounded() {
    let seen = Seen::default();
    // two origins that send the blob to each other
    let (a_l, b_l) = (listener().await, listener().await);
    let (a, b) = (a_l.1.clone(), b_l.1.clone());
    let (to_b, to_a) = (format!("http://{b}/loop"), format!("http://{a}/loop"));
    serve_on(a_l, "ping", &seen, move |_, _| Reply::redirect(302, &to_b));
    serve_on(b_l, "pong", &seen, move |_, _| Reply::redirect(302, &to_a));
    let (client, _dir) = client_of(&insecure(&[&a]), true, &[], &[]);
    let t = client.target(&reference(&a)).unwrap();
    let err = client.get_blob(&t, &digest(), None).await.unwrap_err();
    assert!(err.to_string().contains("too many redirects"), "{err}");
    // (not the probe of the scheme of the first)
    let asked = |server| {
        got(&seen, server)
            .into_iter()
            .filter(|l| !l.starts_with("GET /v2/ "))
            .count()
    };
    assert_eq!((asked("ping"), asked("pong")), (6, 5));
    // a registry that wants a token and refuses every token
    let seen = Seen::default();
    let host = serve("always", &seen, |req, own| match path_of(req) {
        "/token" => Reply::token(),
        _ => Reply::bearer_challenge(&format!("http://{own}/token")),
    })
    .await;
    let (client, _dir) = client_of(&insecure(&[&host]), true, &[], &[]);
    let t = client.target(&reference(&host)).unwrap();
    let resp = client.get_blob(&t, &digest(), None).await.unwrap();
    assert_eq!(resp.status(), 401);
    let count = |prefix: &str| got_under(&seen, "always", prefix).len();
    // (the first `/v2/` is the probe of the scheme)
    assert_eq!(
        (count("/v2/r/blobs/"), count("/v2/ "), count("/token")),
        (3, 2, 2)
    );
}

/// A registry on a public name (here a loopback listener that a name of
/// the tests resolves to) and its `name:port`.
async fn public_registry<F>(server: &'static str, dns: &str, seen: &Seen, handler: F) -> String
where
    F: Fn(&Req, &str) -> Reply + Clone + Send + Sync + 'static,
{
    let l = listener().await;
    let (addr, port) = (
        l.1.parse().unwrap(),
        l.1.rsplit(':').next().unwrap().to_string(),
    );
    hint_tests::name_resolves_to(dns, vec![addr]);
    hint_tests::say_public(dns);
    serve_on(l, server, seen, handler);
    format!("{dns}:{port}")
}

/// What holds: a token endpoint that is not HTTPS is refused for a
/// registry that is not insecure, and not asked; the same for a private
/// address named by the realm or by a redirect of a registry that is not
/// on one, the redirect not kept; a kept redirect that is no longer
/// allowed is dropped when it is to be used.
#[tokio::test]
async fn a_realm_and_a_redirect_are_checked_before_they_are_used_or_kept() {
    let seen = Seen::default();
    // an https registry named a realm over http
    let realm = serve("realm", &seen, |_, _| Reply::token()).await;
    let cert = cert();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let home = l.local_addr().unwrap().to_string();
    let realm_url = format!("http://{realm}/token");
    serve_tls((l, home.clone()), "tls-home", &seen, &cert, move |_, _| {
        Reply::bearer_challenge(&realm_url)
    });
    let (client, _dir) = client_of("", true, &[(&home, &cert)], &[]);
    let t = client.target(&reference(&home)).unwrap();
    let err = client.get_blob(&t, &digest(), None).await.unwrap_err();
    assert!(err.to_string().contains("not HTTPS"), "{err}");
    assert!(got(&seen, "realm").is_empty());

    // a registry on a public name, whose realm is on a private address
    let private_realm = format!("http://{realm}/token");
    let by_realm = public_registry("by-realm", "realm.dns.test", &seen, move |_, _| {
        Reply::bearer_challenge(&private_realm)
    })
    .await;
    let (client, _dir) = client_of(&insecure(&[&by_realm]), true, &[], &[]);
    let t = client.target(&reference(&by_realm)).unwrap();
    let err = client.get_blob(&t, &digest(), None).await.unwrap_err();
    assert!(err.to_string().contains("a private address"), "{err}");
    assert!(got(&seen, "realm").is_empty());

    // one whose blob is on a private address
    let cdn = serve("cdn", &seen, |_, _| Reply::ok(BLOB)).await;
    let to_cdn = format!("http://{cdn}/blob");
    let by_redirect = public_registry("by-redirect", "redirect.dns.test", &seen, move |_, _| {
        Reply::redirect(302, &to_cdn)
    })
    .await;
    let (client, _dir) = client_of(&insecure(&[&by_redirect]), true, &[], &[]);
    let t = client.target(&reference(&by_redirect)).unwrap();
    let err = client.get_blob(&t, &digest(), None).await.unwrap_err();
    assert!(err.to_string().contains("a private address"), "{err}");
    let key = t.blob_key(&digest());
    assert!(client.redirects.get(&key).is_none());
    // a kept redirect to a private address is dropped, not used
    client.redirects.put(&key, &format!("http://{cdn}/kept"));
    assert!(client.get_blob(&t, &digest(), None).await.is_err());
    assert!(client.redirects.get(&key).is_none());
    assert!(got(&seen, "cdn").is_empty());
    assert_eq!(got_under(&seen, "by-redirect", "/v2/r/blobs/").len(), 2);
}

/// What holds: the credentials of an endpoint go to the token endpoint it
/// names and the credentials of another endpoint do not.
#[tokio::test]
async fn an_endpoint_gives_its_own_credentials_to_its_realm_only() {
    let seen = Seen::default();
    let realm_m = serve("realm-m", &seen, |_, _| Reply::token()).await;
    let realm_p = serve("realm-p", &seen, |_, _| Reply::token()).await;
    let mirror = token_registry("mirror", &seen, Some(realm_m), 404).await;
    let primary = token_registry("primary", &seen, Some(realm_p), 200).await;
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n\
         [[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let credentials = [
        (mirror.as_str(), Credentials::basic("mirror-user", "m")),
        (primary.as_str(), Credentials::basic("primary-user", "p")),
    ];
    let (client, _dir) = client_of(&conf, true, &[], &credentials);
    client
        .get_manifest_raw(&reference(&primary), None)
        .await
        .unwrap();
    let scope = "GET /token?service=test&scope=repository%3Ar%3Apull";
    assert_eq!(
        got(&seen, "realm-m"),
        [format!("{scope} {}", basic_of("mirror-user", "m"))]
    );
    assert_eq!(
        got(&seen, "realm-p"),
        [format!("{scope} {}", basic_of("primary-user", "p"))]
    );
}
