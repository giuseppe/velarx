// SPDX-License-Identifier: Apache-2.0
//! An origin of pulls that is an OCI image layout published as static files
//! over HTTP(S): an S3, GCS or Azure bucket, or any web server that serves
//! `index.json`, `oci-layout` and `blobs/sha256/HEX`.
//!
//! ```sh
//! skopeo copy docker://alpine:3 oci:layout:3 && rsync -a layout/ web:/srv/layouts/alpine/
//! velarx pull oci+https://web.example.com/layouts/alpine:3
//! ```
//!
//! The text after the `:` of the last path segment names the image by the
//! `org.opencontainers.image.ref.name` of its entry of `index.json`, the
//! whole name or its tag (`3` takes `docker.io/library/alpine:3`);
//! `@sha256:...` names its manifest, and a layout with one image needs
//! neither.
//! The program keeps nothing between pulls, so the engine starts it for
//! each: the connection to it is its descriptor 3, and it leaves at its end.
//! In `config.toml` (a scheme for each of the two protocols):
//!
//! ```toml
//! [[transports]]
//! scheme = "oci+https"
//! command = ["/usr/local/bin/httplayout"]
//!
//! [[transports]]
//! scheme = "oci+http"
//! command = ["/usr/local/bin/httplayout"]
//! ```
//!
//! What it does not do: it sends no credentials (the layout is read with no
//! authorization, so it is public or open to the network of the host) and
//! no client certificate, it asks for no ranges (a layout has no tags to
//! list either), so its layers are pulled whole and never lazily, and it
//! does not confine itself: it resolves names as the C library does, which
//! reads files of the host, and writes into the staging descriptor each
//! `Unpack` hands it, so a ruleset of nothing but the network does not fit.
//! `--tls-verify=false` is honoured.  The engine checks everything this
//! serves; the interface (`org.velarx.Fetcher`) is
//! `interfaces/org.velarx.Fetcher.varlink`.

use async_trait::async_trait;
use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;
use velarx_content::dir_origin::unpack_layer;
use velarx_content::fetcher::fetch::{Blob, FetchEvent as Event, FetcherError};
use velarx_content::list::HelperSettings;
use velarx_content::serve_fetch::{
    BlobFile, Described, LayerScope, Out, Scope, StagingFetcher, UnpackCall,
};
use velarx_types::digest::Digest;
use velarx_types::transport::ImageLocation;

const REF_NAME: &str = "org.opencontainers.image.ref.name";

struct HttpLayout {
    settings: HelperSettings,
    client: OnceLock<reqwest::Client>,
}

/// The error of a request, as a kind of `std::io::Error`.
fn io_error(e: impl std::fmt::Display, kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::new(kind, e.to_string())
}

/// What the error of a request is to the engine: a file the layout lacks
/// is unavailable, one it refuses is unauthorized.
fn fetch_error(e: std::io::Error) -> FetcherError {
    match e.kind() {
        std::io::ErrorKind::NotFound => FetcherError::unavailable(e.to_string()),
        std::io::ErrorKind::PermissionDenied => FetcherError::unauthorized(e.to_string()),
        _ => FetcherError::failed(e.to_string()),
    }
}

/// The path of the blob `digest` in a layout.
fn blob_path(digest: &Digest) -> String {
    format!("blobs/{}", digest.to_string().replace(':', "/"))
}

/// The base URL of the layout of the location `scope` was opened with, and
/// the name it gives the image.
fn location(scope: &Scope) -> Result<(String, Option<String>), FetcherError> {
    let source = scope.source.as_deref().unwrap_or_default();
    let url = ImageLocation::external_repository(source)
        .and_then(|url| url.strip_prefix("oci+"))
        .ok_or_else(|| FetcherError::InvalidArgument {
            reason: "a location is oci+http://HOST/PATH or oci+https://HOST/PATH".into(),
        })?;
    Ok((url.to_string(), ImageLocation::external_name(source)))
}

/// The body of a response as a `Read`, for a thread of the blocking pool.
struct Body {
    runtime: tokio::runtime::Handle,
    response: reqwest::Response,
    chunk: bytes::Bytes,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.chunk.is_empty() {
            match self.runtime.block_on(self.response.chunk()) {
                Ok(Some(chunk)) => self.chunk = chunk,
                Ok(None) => return Ok(0),
                Err(e) => return Err(io_error(e, std::io::ErrorKind::Other)),
            }
        }
        let n = buf.len().min(self.chunk.len());
        buf[..n].copy_from_slice(&self.chunk.split_to(n));
        Ok(n)
    }
}

/// A successful response to a GET of `url`; the status of a failed one is
/// the kind of the error.
async fn request(client: &reqwest::Client, url: &str) -> std::io::Result<reqwest::Response> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| io_error(e, std::io::ErrorKind::Other))?;
    let status = response.status();
    let kind = match status.as_u16() {
        _ if status.is_success() => return Ok(response),
        404 => std::io::ErrorKind::NotFound,
        401 | 403 => std::io::ErrorKind::PermissionDenied,
        _ => std::io::ErrorKind::Other,
    };
    Err(io_error(format!("{url}: {status}"), kind))
}

impl HttpLayout {
    fn client(&self, scope: &Scope) -> Result<reqwest::Client, FetcherError> {
        if let Some(client) = self.client.get() {
            return Ok(client.clone());
        }
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(scope.tls_verify == Some(false))
            .build()
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        Ok(self.client.get_or_init(|| client).clone())
    }

    /// The file `path` of the layout.
    async fn get(&self, scope: &Scope, path: &str) -> Result<reqwest::Response, FetcherError> {
        let (base, _) = location(scope)?;
        let client = self.client(scope)?;
        request(&client, &format!("{base}/{path}"))
            .await
            .map_err(fetch_error)
    }

    /// The file `path` of the layout, at most `max` bytes.
    async fn small(&self, scope: &Scope, path: &str, max: u64) -> Result<Vec<u8>, FetcherError> {
        let mut response = self.get(scope, path).await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| FetcherError::failed(e.to_string()))?
        {
            if (bytes.len() + chunk.len()) as u64 > max {
                return Err(FetcherError::invalid(format!(
                    "{path} has more than the {max} bytes it may"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

/// Whether the reference name `ref_name` of an entry is `name`, or names
/// it by its tag (`localhost/x:1` is `1`).
fn names(ref_name: &str, name: &str) -> bool {
    let tag = ref_name
        .rsplit_once(':')
        .filter(|(_, t)| !t.contains('/'))
        .map(|(_, t)| t);
    ref_name == name || tag == Some(name)
}

/// The entry of the index `index` that the name `name` takes: its digest
/// and its media type.
fn entry(index: &[u8], name: Option<&str>) -> Result<(String, Option<String>), FetcherError> {
    let index: serde_json::Value = serde_json::from_slice(index)
        .map_err(|e| FetcherError::invalid(format!("index.json: {e}")))?;
    let manifests = index["manifests"].as_array().map_or(&[][..], Vec::as_slice);
    let chosen: Vec<_> = manifests
        .iter()
        .filter(|m| {
            name.is_none_or(|n| {
                m["annotations"][REF_NAME]
                    .as_str()
                    .is_some_and(|r| names(r, n))
            })
        })
        .collect();
    let [one] = chosen.as_slice() else {
        return Err(FetcherError::invalid(format!(
            "index.json has {} images for `{}`: name one as oci+https://HOST/PATH:TAG",
            chosen.len(),
            name.unwrap_or("(no name)")
        )));
    };
    let text = |key| one[key].as_str().map(str::to_string);
    let digest = text("digest").ok_or_else(|| FetcherError::invalid("an entry has no digest"))?;
    Ok((digest, text("mediaType")))
}

fn sealed(bytes: &[u8]) -> Result<File, FetcherError> {
    velarx_base::sealed::sealed_memory(bytes)
        .map(File::from)
        .map_err(|e| FetcherError::failed(e.to_string()))
}

#[async_trait]
impl StagingFetcher for HttpLayout {
    fn described(&self) -> Described {
        Described {
            name: "httplayout".into(),
            capabilities: vec!["metadata".into(), "origin".into()],
            max_objects: 1,
        }
    }

    /// `""` is the image the location names; a digest is a manifest of the
    /// layout.
    async fn get_manifest(
        &self,
        scope: &Scope,
        reference: &str,
        max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        let (digest, media_type) = if reference.is_empty() {
            let index = self.small(scope, "index.json", max).await?;
            let (_, name) = location(scope)?;
            // (`@sha256:...` names the manifest, whatever the index says)
            match name.as_deref().and_then(|n| n.parse::<Digest>().ok()) {
                Some(digest) => (digest.to_string(), None),
                None => entry(&index, name.as_deref())?,
            }
        } else {
            (reference.to_string(), None)
        };
        let digest: Digest = digest
            .parse()
            .map_err(|_| FetcherError::unavailable(format!("{digest}: not here")))?;
        let bytes = self.small(scope, &blob_path(&digest), max).await?;
        Ok((sealed(&bytes)?, media_type))
    }

    async fn get_blob(&self, scope: &Scope, blob: &Blob, file: File) -> Result<(), FetcherError> {
        let mut out = BlobFile::new(file, blob)?;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| FetcherError::InvalidArgument {
                reason: "not the digest of a blob".into(),
            })?;
        let mut response = self.get(scope, &blob_path(&digest)).await?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| FetcherError::failed(e.to_string()))?
        {
            out.write(&chunk)?;
        }
        out.finish()
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let runtime = tokio::runtime::Handle::current();
        let client = self.client(scope)?;
        let base = location(scope)?.0;
        unpack_layer(&self.settings, scope, layer, call, out, move |digest| {
            let response =
                runtime.block_on(request(&client, &format!("{base}/{}", blob_path(digest))))?;
            let size = response
                .content_length()
                .ok_or_else(|| io_error("no Content-Length", std::io::ErrorKind::InvalidData))?;
            Ok((
                Body {
                    runtime,
                    response,
                    chunk: Default::default(),
                },
                size,
            ))
        })
        .await
    }
}

fn main() -> std::io::Result<()> {
    // (first thing: it notes the descriptors it was passed)
    let startup = velarx_sys::fd::Startup::take().expect("the first call");
    let api = std::sync::Arc::new(HttpLayout {
        settings: HelperSettings::of(&velarx_config::Config::default()),
        client: OnceLock::new(),
    });
    let limits = velarx_content::activation::Limits::default();
    velarx_content::serve_fetch::run_descriptor_3(&startup, api, limits)
}
