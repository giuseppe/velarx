// SPDX-License-Identifier: Apache-2.0
//! The files of lazily pulled layers, for the image server that serves the
//! image (`crate::imageserver`): asked of the engine service of the store,
//! which owns the pull (`org.velarx.ImageFetch`, `velarx_content::imagefetch`), the one
//! connection the server has for them.  It knows no fetcher, writes no
//! file and takes no lock of the store.
//!
//! A file that is in neither the store nor the staging of the pull is a
//! `Miss`: the lookup waits (the FUSE file system holds it, one fetch for
//! all its waiters) until the engine says the file has its name, then the
//! file is opened and the kernel's fs-verity measure of it must be its
//! digest before it is used.  What to read ahead of a miss, and in which
//! order the rest of the image comes, is the engine's.
//!
//! When no engine service answers (it went away) the miss fails at once:
//! `EIO` for the container until the next command starts the service.  A
//! connection kept from a service that went is replaced by a new one at
//! once, to the same socket, which the next service binds again; there is
//! no wait and no retry loop.

use crate::imageserver::LazySpec;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use velarx_content::imagefetch::Client;
use velarx_fuse::LazyFileFetcher;
use velarx_storage::FileStore;

pub struct LazyLoader {
    client: Client,
    store: Arc<FileStore>,
    /// The files fetched for the image (the data-only layer after the
    /// objects of the store)
    staging: Arc<FileStore>,
}

impl LazyLoader {
    /// The loader of the image of `spec`, whose files are in `store` or
    /// in `staging`.
    pub fn new(
        spec: &LazySpec,
        connector: Arc<velarx_sys::connector::Connector>,
        (store, staging): (Arc<FileStore>, Arc<FileStore>),
    ) -> Self {
        Self {
            client: Client::through(
                connector,
                spec.proxy.clone(),
                spec.image_id.clone(),
                spec.token.clone(),
            ),
            store,
            staging,
        }
    }

    /// Where the file is, in the store or in the staging.
    fn find(&self, digest: &str) -> Option<PathBuf> {
        self.store
            .get_path(digest)
            .or_else(|| self.staging.get_path(digest))
    }

    /// The startup profile of the image that the engine's fetchers have:
    /// at most `max` digests, empty when nobody has one or no engine
    /// answers in `timeout`.
    pub fn peer_profile(&self, max: usize, timeout: Duration) -> Vec<String> {
        match self.client.profile(
            velarx_content::fetcher::fetch::PROFILE_MAX_BYTES,
            Some(Instant::now() + timeout),
        ) {
            Ok(mut files) => {
                files.retain(|d| velarx_content::pull::is_file_key(d));
                files.truncate(max);
                files
            }
            Err(e) => {
                tracing::debug!("no profile of the peers: {e}");
                Vec::new()
            }
        }
    }
}

impl LazyFileFetcher for LazyLoader {
    fn fetch_file_blocking(
        &self,
        file_digest: &str,
        layer_digest: &str,
        timeout: Option<Duration>,
    ) -> Result<PathBuf, String> {
        if let Some(p) = self.find(file_digest) {
            return Ok(p);
        }
        // (the engine says the class and the party of a failure in its
        // error: the log of the image server shows them, and the reader of
        // the file gets EIO whatever it was)
        self.client
            .miss(
                layer_digest,
                file_digest,
                timeout.map(|t| Instant::now() + t),
            )
            .map_err(|e| format!("the engine: {file_digest}: {e}"))?;
        let path = self
            .find(file_digest)
            .ok_or_else(|| format!("the engine staged {file_digest}, which is not there"))?;
        // (the FUSE file system checks it on the descriptor it serves)
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use velarx_wire::varlink::{call_parameters, encode_error, encode_reply, parse_call, Conn};

    #[derive(serde::Deserialize, Default)]
    struct Open {
        token: String,
    }

    #[derive(serde::Deserialize, Default)]
    struct Miss {
        layer: String,
        digest: String,
    }

    /// An engine that answers each miss with `answer` (`staged`, or the
    /// class of the failure), after `before` (what it does to the staging),
    /// and counts the misses.
    struct Engine {
        socket: PathBuf,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    /// The reply of an engine to the call `bytes` of a connection that was
    /// opened with `token` (None: not yet).
    fn answered(
        bytes: &[u8],
        token: &mut Option<String>,
        answer: &str,
        before: &dyn Fn(&Miss),
        counted: &std::sync::atomic::AtomicUsize,
    ) -> Vec<u8> {
        let head = parse_call(bytes).unwrap();
        match head.method.as_str() {
            "org.velarx.ImageFetch.GetInfo" => encode_reply(
                &serde_json::json!({"name": "engine", "version": "0", "proto": 1,
                    "capabilities": [], "limits": {}}),
                false,
            ),
            "org.velarx.ImageFetch.Open" => {
                let open: Open = call_parameters(bytes).unwrap();
                if open.token != "t0ken" {
                    return encode_error(
                        "org.velarx.ImageFetch.Refused",
                        &serde_json::json!({"reason": "not the token of the pull"}),
                    );
                }
                *token = Some(open.token);
                encode_reply(&serde_json::json!({}), false)
            }
            "org.velarx.ImageFetch.Miss" => {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert!(token.is_some(), "a Miss before Open");
                let miss: Miss = call_parameters(bytes).unwrap();
                assert!(!miss.layer.is_empty());
                before(&miss);
                if answer == "staged" {
                    encode_reply(&serde_json::json!({}), false)
                } else {
                    encode_error(
                        "org.velarx.ImageFetch.Failed",
                        &serde_json::json!({
                            "failure": {"class": answer, "reason": "it did not"},
                            "party": "registry"
                        }),
                    )
                }
            }
            other => panic!("{other}"),
        }
    }

    fn engine(
        dir: &std::path::Path,
        answer: &'static str,
        before: impl Fn(&Miss) + Send + 'static,
    ) -> Engine {
        let socket = dir.join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut conn = Conn::from_stream(stream);
                let mut token = None;
                while let Ok(bytes) = conn.message() {
                    let reply = answered(&bytes, &mut token, answer, &before, &counted);
                    if conn.send(&reply, &[]).is_err() {
                        break;
                    }
                }
            }
        });
        Engine { socket, calls }
    }

    struct Setup {
        _tmp: tempfile::TempDir,
        store: Arc<FileStore>,
        staging: Arc<FileStore>,
    }

    fn setup() -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let staging = Arc::new(FileStore::new(tmp.path().join("staging/files")).unwrap());
        Setup {
            _tmp: tmp,
            store,
            staging,
        }
    }

    fn loader(s: &Setup, socket: PathBuf, token: &str) -> LazyLoader {
        LazyLoader {
            client: Client::new(socket, "a".repeat(64), token.into()),
            store: s.store.clone(),
            staging: s.staging.clone(),
        }
    }

    const DIGEST: &str =
        "fsverity-sha256-12:0000000000000000000000000000000000000000000000000000000000000000";
    const LAYER: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn fetch(l: &LazyLoader) -> Result<PathBuf, String> {
        l.fetch_file_blocking(DIGEST, LAYER, Some(Duration::from_secs(30)))
    }

    /// A file the store has is not asked for.
    #[test]
    fn a_file_that_is_there_is_not_asked_for() {
        let s = setup();
        let tmp = tempfile::tempdir().unwrap();
        let e = engine(tmp.path(), "staged", |_| {});
        let path = s.store.local_path(DIGEST).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(fetch(&loader(&s, e.socket.clone(), "t0ken")), Ok(path));
        assert_eq!(e.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// No engine service runs: the miss fails at once, saying so.
    #[test]
    fn without_an_engine_a_miss_fails_at_once() {
        let s = setup();
        let tmp = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let e = fetch(&loader(&s, tmp.path().join("none"), "t0ken")).unwrap_err();
        assert!(e.contains("no engine service serves the pulls"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// What the engine says is not believed: a file it says is staged
    /// and is not there is refused (what is there is checked by the FUSE
    /// file system on the descriptor it serves).
    #[test]
    fn a_staged_file_must_be_there() {
        let s = setup();
        let tmp = tempfile::tempdir().unwrap();
        let e = engine(tmp.path(), "staged", |_| {});
        let l = loader(&s, e.socket.clone(), "t0ken");
        let err = fetch(&l).unwrap_err();
        assert!(err.contains("which is not there"), "{err}");
    }

    /// A refusal and a failure of the engine are the read's error.
    #[test]
    fn what_the_engine_could_not_do_is_an_error() {
        let s = setup();
        let tmp = tempfile::tempdir().unwrap();
        let e = engine(tmp.path(), "failed", |_| {});
        let err = fetch(&loader(&s, e.socket.clone(), "t0ken")).unwrap_err();
        // (the log names the class and the party)
        assert!(err.contains("failed: it did not (party registry)"), "{err}");
        let err = fetch(&loader(&s, e.socket.clone(), "other")).unwrap_err();
        assert!(err.contains("Refused"), "{err}");
        let tmp2 = tempfile::tempdir().unwrap();
        let e2 = engine(tmp2.path(), "unavailable", |m| assert_eq!(m.digest, DIGEST));
        let err = fetch(&loader(&s, e2.socket.clone(), "t0ken")).unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
    }

    /// The engine went and another bound the same socket: the kept
    /// connection is replaced by one to the new engine at once.
    #[test]
    fn a_new_engine_on_the_same_socket_is_asked() {
        let s = setup();
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("engine.sock");
        // the first engine answers one call, then goes
        let first = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = first.accept().unwrap();
            let mut conn = Conn::from_stream(stream);
            let mut token = None;
            // (GetInfo, Open, then the miss it fails)
            for _ in 0..3 {
                let bytes = conn.message().unwrap();
                let reply = answered(&bytes, &mut token, "failed", &|_| {}, &Default::default());
                conn.send(&reply, &[]).unwrap();
            }
        });
        let l = loader(&s, socket.clone(), "t0ken");
        assert!(fetch(&l).is_err());
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        let e = engine(tmp.path(), "unavailable", |_| {});
        let err = fetch(&l).unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
        assert_eq!(e.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
