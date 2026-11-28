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

use std::io::Read;
use std::sync::OnceLock;
use velarx_content::blob_fetch::{BlobFetch, Blobs};
use velarx_content::fetcher::fetch::FetcherError;
use velarx_content::list::HelperSettings;
use velarx_content::serve_fetch::Scope;
use velarx_types::digest::Digest;
use velarx_types::transport::ImageLocation;

const REF_NAME: &str = "org.opencontainers.image.ref.name";

struct HttpLayout {
    client: OnceLock<reqwest::blocking::Client>,
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

impl HttpLayout {
    /// The file `path` of the layout of `scope`; a file the layout lacks is
    /// unavailable, one it refuses is unauthorized.
    fn get(&self, scope: &Scope, path: &str) -> Result<reqwest::blocking::Response, FetcherError> {
        let client = match self.client.get() {
            Some(client) => client,
            None => {
                let client = reqwest::blocking::Client::builder()
                    .danger_accept_invalid_certs(scope.tls_verify == Some(false))
                    .build()
                    .map_err(|e| FetcherError::failed(e.to_string()))?;
                self.client.get_or_init(|| client)
            }
        };
        let url = format!("{}/{path}", location(scope)?.0);
        let response = client
            .get(&url)
            .send()
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        let status = response.status();
        let reason = format!("{url}: {status}");
        match status.as_u16() {
            _ if status.is_success() => Ok(response),
            404 => Err(FetcherError::unavailable(reason)),
            401 | 403 => Err(FetcherError::unauthorized(reason)),
            _ => Err(FetcherError::failed(reason)),
        }
    }
}

/// The path of the blob `digest` in a layout.
fn blob_path(digest: &Digest) -> String {
    format!("blobs/{}", digest.to_string().replace(':', "/"))
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
fn entry(index: &[u8], name: Option<&str>) -> Result<(Digest, Option<String>), FetcherError> {
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
    let digest = text("digest")
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| FetcherError::invalid("an entry has no digest"))?;
    Ok((digest, text("mediaType")))
}

impl Blobs for HttpLayout {
    fn open(
        &self,
        scope: &Scope,
        digest: &Digest,
    ) -> Result<(Box<dyn std::io::Read + Send>, u64), FetcherError> {
        let response = self.get(scope, &blob_path(digest))?;
        let size = response
            .content_length()
            .ok_or_else(|| FetcherError::failed("no Content-Length"))?;
        Ok((Box::new(response), size))
    }

    /// The image the location names: by the digest it gives (`@sha256:...`,
    /// whatever the index says) or by the name it gives in `index.json`.
    fn resolve(&self, scope: &Scope, max: u64) -> Result<(Digest, Option<String>), FetcherError> {
        let name = location(scope)?.1;
        if let Some(digest) = name.as_deref().and_then(|n| n.parse().ok()) {
            return Ok((digest, None));
        }
        let mut index = Vec::new();
        self.get(scope, "index.json")?
            .take(max.saturating_add(1))
            .read_to_end(&mut index)?;
        if index.len() as u64 > max {
            return Err(FetcherError::invalid(format!("larger than {max} bytes")));
        }
        entry(&index, name.as_deref())
    }
}

fn main() -> std::io::Result<()> {
    velarx_content::serve_fetch::main(|| {
        let settings = HelperSettings::of(&velarx_config::Config::default());
        let client = OnceLock::new();
        BlobFetch::new("httplayout", settings, HttpLayout { client })
    })
}
