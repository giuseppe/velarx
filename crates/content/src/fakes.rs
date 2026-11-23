// SPDX-License-Identifier: Apache-2.0
//! Fetchers for the tests of the crates above this one (`test-support`): they
//! stage one file on the interface of the real fetchers, with the bytes its
//! name says or with other ones.

use crate::fetcher::fetch::{EventKind, FetchEvent as Event, FetcherError};
use crate::serve_fetch::{Described, FetchCall, LayerScope, Out, Scope, StagingFetcher};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// What a fake fetcher stages for the file it is asked for.
#[derive(Clone, Copy)]
pub enum Stages {
    /// The bytes the name says
    Right,
    /// Other bytes
    Wrong,
}

/// A fetcher of files by their fs-verity keys, with their bytes.
pub struct Fake {
    how: Stages,
    /// The files it has: key, bytes
    files: Vec<(String, Vec<u8>)>,
    asked: Arc<AtomicUsize>,
}

impl Fake {
    /// A fetcher that stages the file `key` as `how`; `asked` counts its
    /// calls to `fetch`.
    pub fn new(how: Stages, key: &str, body: &[u8], asked: Arc<AtomicUsize>) -> Self {
        Self::of(how, vec![(key.to_string(), body.to_vec())], asked)
    }

    /// A fetcher that stages each file of `files` (key, bytes) as `how`.
    pub fn of(how: Stages, files: Vec<(String, Vec<u8>)>, asked: Arc<AtomicUsize>) -> Self {
        Self { how, files, asked }
    }
}

#[async_trait]
impl StagingFetcher for Fake {
    fn described(&self) -> Described {
        Described {
            name: "fake".into(),
            capabilities: vec!["objects".into(), "metadata".into()],
            max_objects: 8,
        }
    }

    async fn fetch(
        &self,
        _scope: &Scope,
        layer: &LayerScope,
        call: FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        use std::io::Write;
        self.asked.fetch_add(1, Ordering::SeqCst);
        let failed = |e: String| FetcherError::failed(e);
        for name in &call.objects {
            let Some((_, body)) = self.files.iter().find(|(k, _)| k == name) else {
                return Err(failed(format!("{name} is not a file of this fetcher")));
            };
            let rel = crate::stager::staged_rel(name).ok_or_else(|| failed("no key".into()))?;
            let (dir, _) = rel
                .rsplit_once('/')
                .ok_or_else(|| failed("no dir".into()))?;
            for part in ["files", dir] {
                match rustix::fs::mkdirat(
                    &layer.staging,
                    part,
                    rustix::fs::Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(failed(e.to_string())),
                }
            }
            let file = rustix::fs::openat(
                &layer.staging,
                rel.as_str(),
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(|e| failed(e.to_string()))?;
            let body: &[u8] = match self.how {
                Stages::Right => body,
                Stages::Wrong => b"not it",
            };
            std::fs::File::from(file)
                .write_all(body)
                .map_err(|e| failed(e.to_string()))?;
        }
        let staged = Event {
            objects: (0..call.objects.len() as u32).collect(),
            ..Event::of(EventKind::Staged)
        };
        out.send(staged)
            .await
            .map_err(|_| failed("gone".to_string()))
    }
}

/// A fetcher that has one manifest and one blob, as bytes it sends for any
/// digest asked (so they may be the wrong ones).
pub struct Metadata(pub Vec<u8>);

#[async_trait]
impl StagingFetcher for Metadata {
    fn described(&self) -> Described {
        Described {
            name: "metadata".into(),
            capabilities: vec!["metadata".into()],
            max_objects: 1,
        }
    }

    async fn get_manifest(
        &self,
        _scope: &Scope,
        _reference: &str,
        _max: u64,
    ) -> Result<(std::fs::File, Option<String>), FetcherError> {
        let file = velarx_base::sealed::sealed_memory(&self.0)
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        Ok((file.into(), None))
    }

    async fn get_blob(
        &self,
        _scope: &Scope,
        _blob: &crate::fetcher::fetch::Blob,
    ) -> Result<std::fs::File, FetcherError> {
        let file = velarx_base::sealed::sealed_memory(&self.0)
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        Ok(file.into())
    }

    async fn get_signatures(
        &self,
        _scope: &Scope,
        _reference: &str,
        _max: u64,
    ) -> Result<std::fs::File, FetcherError> {
        let file = velarx_base::sealed::sealed_memory(&self.0)
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        Ok(file.into())
    }
}
