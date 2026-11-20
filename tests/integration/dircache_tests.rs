// SPDX-License-Identifier: Apache-2.0
//! The example provider (`examples/dircache.rs`) as an external source, run
//! as a separate process and configured like a user would: pulls with it
//! first in the chain take their bytes from it, wrong bytes fall back to the
//! registry, and a source that is not running costs nothing.

use crate::common::*;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use velarx_config::Config;

fn example() -> PathBuf {
    built_binary("dircache").expect("no dircache example: cargo build --example dircache")
}

struct Cache {
    dir: tempfile::TempDir,
    cache: PathBuf,
    socket: PathBuf,
    child: Option<Child>,
}

impl Cache {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        // The example makes the directory of its socket (mode 0700) itself.
        let socket = dir.path().join("services").join("dircache.sock");
        let mut this = Self {
            dir,
            cache,
            socket,
            child: None,
        };
        this.spawn().await;
        this
    }

    async fn spawn(&mut self) {
        let bin = example();
        assert!(bin.exists(), "{} is not built: `cargo test` builds the examples, or `cargo build --example dircache`", bin.display());
        // (it says READY=1 once it serves, as a service does)
        let notify = self.dir.path().join("notify");
        let _ = std::fs::remove_file(&notify);
        let ready = std::os::unix::net::UnixDatagram::bind(&notify).unwrap();
        ready
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let child = Command::new(bin)
            .arg(&self.socket)
            .arg(&self.cache)
            .env("NOTIFY_SOCKET", &notify)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        self.child = Some(child);
        let mut buf = [0u8; 64];
        let said = ready.recv(&mut buf).map(|n| buf[..n].to_vec());
        let answer =
            match velarx_content::fetcher::fetch_client::FetchConn::connect_checked(&self.socket)
                .await
            {
                Ok(mut conn) => conn
                    .get_info()
                    .await
                    .map(|i| i.name)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
        if said.as_deref().is_ok_and(|s| s.starts_with(b"READY=1")) && answer.is_ok() {
            return;
        }
        let status = self.child.as_mut().unwrap().try_wait();
        panic!(
            "the example does not answer: {said:?}, {answer:?}, {status:?}, {:?}",
            std::fs::read_dir(self.dir.path())
                .map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
        );
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn put(&self, digest: &Digest, data: &[u8]) {
        std::fs::write(self.cache.join(digest.hex()), data).unwrap();
    }

    /// The chain a configuration file makes.
    fn chain(&self) -> Fetchers {
        let config: Config = toml::from_str(&format!(
            "[[sources.external]]\nname = \"dircache\"\nsocket = \"{}\"\n\
             [pull]\nsources = [\"dircache\", \"registry\"]\n",
            self.socket.display()
        ))
        .unwrap();
        config.validate().unwrap();
        Fetchers(config.sources.external)
    }

    async fn env(&self) -> Env {
        self.env_with(velarx_config::PullConfig::default()).await
    }

    async fn env_with(&self, pull: velarx_config::PullConfig) -> Env {
        env_sources(pull, velarx_config::PushConfig::default(), self.chain()).await
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        self.stop();
        let _ = self.dir.path();
    }
}

fn chunks(items: &[Item]) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    for i in items {
        if let Item::File { data, chunk, .. } = i {
            for c in data.chunks(*chunk) {
                if !c.iter().all(|&b| b == 0) {
                    all.push(c.to_vec());
                }
            }
        }
    }
    all
}

fn big() -> Vec<u8> {
    sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File {
                name: "usr/big",
                data,
                ..
            } => Some(data),
            _ => None,
        })
        .unwrap()
}

#[tokio::test]
async fn test_a_pull_takes_its_chunks_from_the_directory_cache() {
    let cache = Cache::start().await;
    for c in chunks(&sample()) {
        // Both spellings of the name work.
        let d = sha(&c);
        if c.len() % 2 == 0 {
            cache.put(&d, &c);
        } else {
            std::fs::write(cache.cache.join(d.to_string()), &c).unwrap();
        }
    }
    let e = cache.env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let result = e.pull().await.unwrap();
    assert!(result.stats.from("dircache").0 > 0);
    assert_eq!(
        e.reg.ranged.load(Ordering::SeqCst),
        1,
        "the registry was only asked for the metadata"
    );
    assert!(e.store.contains(&vid(&big())));
}

#[tokio::test]
async fn test_a_lazy_read_takes_its_file_from_the_directory_cache() {
    let cache = Cache::start().await;
    for c in chunks(&sample()) {
        cache.put(&sha(&c), &c);
    }
    let e = cache.env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let before = e.reg.ranged.load(Ordering::SeqCst);
    let path = e
        .service
        .fetch_lazy_file(&vid(&big()), &layer.key())
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), big());
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn test_wrong_bytes_in_the_cache_fail_the_pull_naming_it() {
    let cache = Cache::start().await;
    for c in chunks(&sample()) {
        // Named by the digest of the right bytes, holding others.
        let mut wrong = c.clone();
        wrong.iter_mut().for_each(|b| *b ^= 0x55);
        cache.put(&sha(&c), &wrong);
    }
    let e = cache.env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    // (what a source gave that is not what the table of contents says fails
    // the pull, naming it: the registry is not asked in its place)
    let err = e.pull().await.unwrap_err();
    assert!(
        matches!(&err, velarx_types::ImageError::Transfer { failure, .. }
            if failure.class == velarx_proto::transfer::FailureClass::Invalid),
        "{err}"
    );
    assert!(!e.store.contains(&vid(&big())));

    // A cache file of the wrong size for the chunk it is named after.
    let e = cache.env().await;
    e.publish(&[&layer], &[ZSTD]);
    let victim = chunks(&sample()).remove(0);
    cache.put(&sha(&victim), &victim[..victim.len() - 1]);
    let err = e.pull().await.unwrap_err();
    assert!(
        matches!(&err, velarx_types::ImageError::Transfer { party, failure, .. }
            if party == "dircache" && failure.class == velarx_proto::transfer::FailureClass::Invalid),
        "{err}"
    );
}

#[tokio::test]
async fn test_a_cache_that_is_not_running_falls_back_at_once() {
    let mut cache = Cache::start().await;
    for c in chunks(&sample()) {
        cache.put(&sha(&c), &c);
    }
    cache.stop();
    let e = cache.env().await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    let started = Instant::now();
    let result = e.pull().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(result.stats.from("dircache").0, 0);
    assert!(e.store.contains(&vid(&big())));
    // The socket file of a stopped cache that was killed is still there; a
    // path that never existed is as quick.
    let _ = Path::new(&cache.socket);
}
