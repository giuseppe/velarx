// SPDX-License-Identifier: Apache-2.0
//! A registry for the cases that pull by ranges: it serves blobs with
//! `Range` (a single `206` part, or `multipart/byteranges` for several),
//! notes every request it gets, and can hang up after a number of them.
//! The pulls reach it as every pull reaches a registry: through the registry
//! fetcher, whose confined workers are `velarx-registry` processes (the
//! binary built next to the tests, `cargo build --bins`, or
//! `VELARX_TEST_REGISTRY`); here the fetcher runs in a thread of the test.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use velarx_content::pull::staged_fetch::StagedFetch;
use velarx_content::pull::Source;
use velarx_content::serve_fetch::LocalFetcher;
use velarx_registry::client::RegistryClient;
use velarx_registry::target::EndpointSpec;
use velarx_types::OciDescriptor;

/// A request for a blob: the ranges it asked for (none: the whole blob).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRequest {
    pub digest: String,
    pub ranges: Vec<Range<u64>>,
}

impl BlobRequest {
    /// The bytes it asked for, given the size of the blob.
    pub fn bytes(&self, size: u64) -> u64 {
        if self.ranges.is_empty() {
            return size;
        }
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }
}

/// The registry, and what it was asked.
pub struct Registry {
    host: String,
    blobs: Arc<Mutex<HashMap<String, Arc<Vec<u8>>>>>,
    log: Arc<Mutex<Vec<BlobRequest>>>,
    /// Blob requests it answers before it hangs up on the next ones
    /// (usize::MAX: it never does).
    budget: Arc<AtomicUsize>,
    /// What runs once the blob request of that number was logged
    hook: Hook,
    /// The registry fetchers of the pulls, kept while the registry is
    fetchers: Mutex<Vec<LocalFetcher>>,
}

/// What runs once, at the blob request of the given number.
type Hook = Arc<Mutex<Option<(usize, Box<dyn FnOnce() + Send>)>>>;

/// The registry fetcher binary: `VELARX_TEST_REGISTRY`, else the one built
/// next to the test.
fn registry_binary() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("VELARX_TEST_REGISTRY").filter(|p| !p.is_empty()) {
        return path.into();
    }
    velarx_base::testing::built_binary("velarx-registry").expect(
        "no velarx-registry binary next to the tests: build it first (`cargo build --bins`, \
         or `make test`) or set VELARX_TEST_REGISTRY",
    )
}

fn parse_ranges(value: &str, total: u64) -> Option<Vec<Range<u64>>> {
    let spec = value.trim().strip_prefix("bytes=")?;
    spec.split(',')
        .map(|part| {
            let (a, b) = part.trim().split_once('-')?;
            if a.is_empty() {
                // the last `b` bytes
                let n: u64 = b.parse().ok()?;
                return Some(total.saturating_sub(n)..total);
            }
            let start: u64 = a.parse().ok()?;
            let end: u64 = if b.is_empty() {
                total
            } else {
                b.parse::<u64>().ok()?.checked_add(1)?.min(total)
            };
            Some(start..end)
        })
        .collect()
}

async fn serve(
    mut sock: tokio::net::TcpStream,
    blobs: Arc<Mutex<HashMap<String, Arc<Vec<u8>>>>>,
    log: Arc<Mutex<Vec<BlobRequest>>>,
    budget: Arc<AtomicUsize>,
    hook: Hook,
) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // the head of the next request
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            // (a TLS hello from a client that tries https first: this
            // registry speaks plain HTTP, and says so by hanging up)
            if buf.first().is_some_and(|b| !b.is_ascii_uppercase()) {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let mut lines = head.lines();
        let request = lines.next().unwrap_or_default().to_string();
        let mut parts = request.split(' ');
        let (method, path) = (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default().to_string(),
        );
        let range = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .map(|(_, v)| v.trim().to_string());
        let reply = |status: &str, headers: &str, body: &[u8]| {
            let mut out = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}\r\n",
                body.len()
            )
            .into_bytes();
            if method != "HEAD" {
                out.extend_from_slice(body);
            }
            out
        };
        let out = if path == "/v2/" {
            reply("200 OK", "", b"")
        } else if let Some(digest) = path.strip_prefix("/v2/r/blobs/") {
            let blob = blobs.lock().unwrap().get(digest).cloned();
            match blob {
                None => reply("404 Not Found", "", b""),
                Some(blob) => {
                    let total = blob.len() as u64;
                    let ranges = range
                        .as_deref()
                        .and_then(|r| parse_ranges(r, total))
                        .unwrap_or_default();
                    if method == "GET" {
                        let number = {
                            let mut log = log.lock().unwrap();
                            log.push(BlobRequest {
                                digest: digest.to_string(),
                                ranges: ranges.clone(),
                            });
                            log.len()
                        };
                        let due = {
                            let mut hook = hook.lock().unwrap();
                            match hook.take() {
                                Some((at, f)) if at == number => Some(f),
                                other => {
                                    *hook = other;
                                    None
                                }
                            }
                        };
                        if let Some(f) = due {
                            f();
                        }
                        // (the requests after the budget are never answered)
                        let left = budget.load(Ordering::SeqCst);
                        if left == 0 {
                            return;
                        }
                        if left != usize::MAX {
                            budget.store(left - 1, Ordering::SeqCst);
                        }
                    }
                    match ranges.as_slice() {
                        [] => reply("200 OK", "Accept-Ranges: bytes\r\n", &blob),
                        [r] => reply(
                            "206 Partial Content",
                            &format!(
                                "Content-Range: bytes {}-{}/{total}\r\nContent-Type: application/octet-stream\r\n",
                                r.start,
                                r.end - 1
                            ),
                            &blob[r.start as usize..r.end as usize],
                        ),
                        many => {
                            let mut body = Vec::new();
                            for r in many {
                                body.extend_from_slice(
                                    format!(
                                        "--BOUND\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {}-{}/{total}\r\n\r\n",
                                        r.start,
                                        r.end - 1
                                    )
                                    .as_bytes(),
                                );
                                body.extend_from_slice(&blob[r.start as usize..r.end as usize]);
                                body.extend_from_slice(b"\r\n");
                            }
                            body.extend_from_slice(b"--BOUND--\r\n");
                            reply(
                                "206 Partial Content",
                                "Content-Type: multipart/byteranges; boundary=BOUND\r\n",
                                &body,
                            )
                        }
                    }
                }
            }
        } else {
            reply("404 Not Found", "", b"")
        };
        if sock.write_all(&out).await.is_err() {
            return;
        }
    }
}

impl Registry {
    /// A registry on a port of the loopback, with no blob.
    pub async fn start() -> Self {
        Self::start_blocking()
    }

    /// The same, for a function that is not async (inside a runtime).
    pub fn start_blocking() -> Self {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let blobs = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let budget = Arc::new(AtomicUsize::new(usize::MAX));
        let hook: Hook = Arc::default();
        {
            let (blobs, log, budget, hook) =
                (blobs.clone(), log.clone(), budget.clone(), hook.clone());
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    tokio::spawn(serve(
                        sock,
                        blobs.clone(),
                        log.clone(),
                        budget.clone(),
                        hook.clone(),
                    ));
                }
            });
        }
        Self {
            host,
            blobs,
            log,
            budget,
            hook,
            fetchers: Mutex::default(),
        }
    }

    /// Serve `bytes` as the blob `digest`.
    pub fn put(&self, digest: &str, bytes: Vec<u8>) {
        self.blobs
            .lock()
            .unwrap()
            .insert(digest.to_string(), Arc::new(bytes));
    }

    /// The blob requests so far.
    pub fn requests(&self) -> Vec<BlobRequest> {
        self.log.lock().unwrap().clone()
    }

    /// Run `f` once, when the blob request number `at` (from 1, counted since
    /// the registry started) arrives (before it is answered): a test stops
    /// something at a point of a pull this way.
    pub fn at_request(&self, at: usize, f: impl FnOnce() + Send + 'static) {
        *self.hook.lock().unwrap() = Some((at, Box::new(f)));
    }

    /// Hang up on the blob requests that come after the next `n`.
    pub fn answer_only(&self, n: usize) {
        self.budget.store(n, Ordering::SeqCst);
    }

    /// Answer every request again.
    pub fn answer_all(&self) {
        self.budget.store(usize::MAX, Ordering::SeqCst);
    }

    /// The registry fetcher of a pull of the layers `layers` from this
    /// registry, with the staging of the layers beneath
    /// `staging`, and where the layers are pulled from.
    pub async fn staged(
        &self,
        staging: &std::path::Path,
        layers: &[OciDescriptor],
    ) -> (Arc<StagedFetch>, Source) {
        let spec = EndpointSpec {
            host: self.host.clone(),
            repository: "r".into(),
            insecure: true,
            allow_private: true,
            credentials: None,
            certs: Default::default(),
            brokered: false,
            hint: None,
            hints: false,
            min_speed: Default::default(),
        };
        let (fetch_client, target) = RegistryClient::from_specs(&[spec]).unwrap();
        let pull = velarx_config::PullConfig {
            worker_path: Some(registry_binary()),
            ..Default::default()
        };
        // (the workers are started by a process forked before this test
        // has threads of its own to run; one for the binary of all)
        static SPAWNER: std::sync::OnceLock<std::sync::Arc<velarx_sys::spawner::Spawner>> =
            std::sync::OnceLock::new();
        let spawner = SPAWNER
            .get_or_init(|| {
                std::sync::Arc::new(
                    velarx_sys::spawner::Spawner::start_beside_idle_threads(
                        vec![
                            velarx_registry_lib::net::pool::worker_program(&registry_binary())
                                .expect("the worker program"),
                        ],
                        |_| Ok(()),
                    )
                    .expect("the worker spawner"),
                )
            })
            .clone();
        let service = velarx_registry_lib::registry::RegistryService::with_client(
            (pull, velarx_config::PushConfig::default()),
            fetch_client,
            spawner,
        )
        .expect("the registry service");
        std::fs::create_dir_all(staging).expect("the staging directory");
        let local = LocalFetcher::start(
            velarx_registry_lib::registry_fetch::RegistryFetch::new(
                service,
                std::sync::Arc::new(
                    std::fs::File::open(staging)
                        .expect("the staging directory")
                        .into(),
                ),
            ),
            velarx_content::activation::Limits::default(),
        )
        .expect("the registry fetcher");
        let conn = velarx_content::fetcher::fetch_client::FetchConn::new(
            local
                .connect()
                .expect("a connection to the registry fetcher"),
        )
        .unwrap();
        self.fetchers.lock().unwrap().push(local);
        let manifest = velarx_types::OciManifest {
            schema_version: 2,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".into()),
            config: OciDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".into(),
                digest: velarx_types::digest::Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"{}",
                ),
                size: 2,
                annotations: Default::default(),
            },
            layers: layers.to_vec(),
            annotations: Default::default(),
        };
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let staged = StagedFetch::open(
            Vec::new(),
            conn,
            staging,
            false,
            (&format!("{}/r", self.host), false),
            None,
            &manifest,
        )
        .await
        .expect("the list of the pull");
        (staged, Source::Registry(target))
    }
}
