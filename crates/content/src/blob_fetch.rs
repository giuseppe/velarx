// SPDX-License-Identifier: Apache-2.0
//! A fetcher that is "the blob of a digest": the whole of a fetcher that
//! serves an origin of pulls (a layout on a web server, an archive, a
//! bucket) is [`Blobs`].  [`BlobFetch`] makes of it what the engine asks:
//! the manifest the location names (`GetFile`), a blob (`GetBlob`), the
//! files of a layer that has no table of contents (`Unpack`) and the words
//! a fetcher says of itself.  The engine checks everything it is given.

use crate::dir_origin::unpack_layer;
use crate::fetcher::fetch::{sealed, Blob, FetchEvent, FetcherError, FileKind};
use crate::list::HelperSettings;
use crate::serve_fetch::UnpackCall;
use crate::serve_fetch::{BlobFile, Described, LayerScope, Out, Scope, StagingFetcher};
use async_trait::async_trait;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use velarx_types::digest::Digest;

/// What an origin has: its blobs by digest, and the manifest its location
/// names.  The calls block (they run on threads of the blocking pool) and
/// what they give is untrusted.
pub trait Blobs: Send + Sync + 'static {
    /// The scope is open: what the origin does before the first call (the
    /// origin of a path confines its process here).
    fn opened(&self, _scope: &Scope) -> Result<(), FetcherError> {
        Ok(())
    }

    /// The blob of `digest` and its length; an error of kind `NotFound`
    /// when the origin lacks it.
    fn open(
        &self,
        scope: &Scope,
        digest: &Digest,
    ) -> Result<(Box<dyn Read + Send>, u64), FetcherError>;

    /// The manifest (or index) the location of the scope names, as the
    /// digest of a blob that [`Blobs::open`] gives and its media type, if
    /// known; at most `max` bytes.
    fn resolve(&self, scope: &Scope, max: u64) -> Result<(Digest, Option<String>), FetcherError>;
}

/// The [`StagingFetcher`] of a [`Blobs`].
pub struct BlobFetch<B> {
    name: &'static str,
    settings: HelperSettings,
    blobs: Arc<B>,
}

impl<B: Blobs> BlobFetch<B> {
    /// The fetcher `name` of `blobs`, with the default limits for the layers
    /// it unpacks.
    pub fn new(name: &'static str, blobs: B) -> Arc<Self> {
        Self::with_settings(
            name,
            HelperSettings::of(&velarx_config::Config::default()),
            blobs,
        )
    }

    /// [`BlobFetch::new`] with the limits `settings` for the layers it
    /// unpacks.
    pub fn with_settings(name: &'static str, settings: HelperSettings, blobs: B) -> Arc<Self> {
        Arc::new(Self {
            name,
            settings,
            blobs: Arc::new(blobs),
        })
    }
}

/// `work` on a thread of the blocking pool.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, FetcherError> + Send + 'static,
) -> Result<T, FetcherError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| FetcherError::failed(e.to_string()))?
}

fn blob_digest(blob: &Blob) -> Result<Digest, FetcherError> {
    blob.digest
        .parse()
        .map_err(|_| FetcherError::InvalidArgument {
            reason: "not the digest of a blob".into(),
        })
}

#[async_trait]
impl<B: Blobs> StagingFetcher for BlobFetch<B> {
    fn described(&self) -> Described {
        Described {
            name: self.name.into(),
            capabilities: Vec::new(),
            max_objects: 1,
        }
    }

    async fn opened(&self, scope: &Scope) -> Result<(), FetcherError> {
        self.blobs.opened(scope)
    }

    /// The manifest: none is the one the location names; a digest is a blob
    /// of the origin.  An origin has no other small file.
    async fn get_file(
        &self,
        scope: &Scope,
        kind: FileKind,
        reference: Option<&str>,
        max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        if kind != FileKind::Manifest {
            return Err(FetcherError::unavailable("not here"));
        }
        let (blobs, scope) = (self.blobs.clone(), scope.clone());
        let reference = reference.map(str::to_string);
        let (bytes, media_type) = blocking(move || {
            let (digest, media_type) = match reference {
                None => blobs.resolve(&scope, max)?,
                Some(reference) => {
                    let digest = reference
                        .parse()
                        .map_err(|_| FetcherError::unavailable(format!("{reference}: not here")))?;
                    (digest, None)
                }
            };
            let (from, _) = blobs.open(&scope, &digest)?;
            let mut bytes = Vec::new();
            from.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
            Ok((bytes, media_type))
        })
        .await?;
        if bytes.len() as u64 > max {
            return Err(FetcherError::invalid(format!("larger than {max} bytes")));
        }
        Ok((sealed(&bytes)?, media_type))
    }

    async fn get_blob(
        &self,
        scope: &Scope,
        blob: &Blob,
        mut out: BlobFile,
    ) -> Result<(), FetcherError> {
        let digest = blob_digest(blob)?;
        let (blobs, scope) = (self.blobs.clone(), scope.clone());
        blocking(move || {
            let (mut from, _) = blobs.open(&scope, &digest)?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = from.read(&mut buf)?;
                if n == 0 {
                    return out.finish();
                }
                out.write(&buf[..n])?;
            }
        })
        .await
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<FetchEvent>,
    ) -> Result<(), FetcherError> {
        let (blobs, opened) = (self.blobs.clone(), scope.clone());
        unpack_layer(&self.settings, scope, layer, call, out, move |digest| {
            blobs.open(&opened, digest)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::fetch::FailureClass;

    /// An origin of one blob.
    struct One(Vec<u8>);

    impl Blobs for One {
        fn open(
            &self,
            _: &Scope,
            digest: &Digest,
        ) -> Result<(Box<dyn Read + Send>, u64), FetcherError> {
            if *digest != crate::sha256(&self.0) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            }
            Ok((
                Box::new(std::io::Cursor::new(self.0.clone())),
                self.0.len() as u64,
            ))
        }

        fn resolve(&self, _: &Scope, _: u64) -> Result<(Digest, Option<String>), FetcherError> {
            Ok((crate::sha256(&self.0), Some("text/plain".into())))
        }
    }

    fn scope() -> Scope {
        Scope {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle: std::time::Duration::from_secs(30),
            kept: Arc::default(),
        }
    }

    fn read(file: &File) -> Vec<u8> {
        let mut bytes = vec![0u8; file.metadata().unwrap().len() as usize];
        std::os::unix::fs::FileExt::read_exact_at(file, &mut bytes, 0).unwrap();
        bytes
    }

    #[tokio::test]
    async fn a_fetcher_of_blobs_gives_the_manifest_and_the_blobs_of_the_origin() {
        let data = b"the manifest".to_vec();
        let digest = crate::sha256(&data);
        let fetcher = BlobFetch::new("one", One(data.clone()));
        let (file, media_type) = fetcher
            .get_file(&scope(), FileKind::Manifest, None, 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            (read(&file), media_type.as_deref()),
            (data.clone(), Some("text/plain"))
        );
        let (file, media_type) = fetcher
            .get_file(
                &scope(),
                FileKind::Manifest,
                Some(&digest.to_string()),
                1 << 20,
            )
            .await
            .unwrap();
        assert_eq!((read(&file), media_type), (data.clone(), None));
        let larger = fetcher
            .get_file(&scope(), FileKind::Manifest, None, 4)
            .await;
        assert!(matches!(
            larger.unwrap_err().failure(),
            Some(f) if f.class == FailureClass::Invalid
        ));
        let blob = Blob {
            digest: digest.to_string(),
            size: data.len() as u64,
            media_type: "text/plain".into(),
            annotations: None,
        };
        let file = tempfile::tempfile().unwrap();
        fetcher
            .get_blob(
                &scope(),
                &blob,
                BlobFile::new(file.try_clone().unwrap(), &blob).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read(&file), data);
        let absent = Blob {
            digest: crate::sha256(b"absent").to_string(),
            ..blob
        };
        let e = fetcher
            .get_blob(
                &scope(),
                &absent,
                BlobFile::new(tempfile::tempfile().unwrap(), &absent).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            e.failure().map(|f| f.class),
            Some(FailureClass::Unavailable)
        );
    }
}
