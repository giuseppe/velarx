// SPDX-License-Identifier: Apache-2.0
//! The signatures of an image as the registry has them, for a `GetFile` of signatures:
//! where registries.d says (a lookaside storage on the network, the layers
//! of the sigstore attachment of the manifest).  A lookaside storage in a
//! directory (`file:`) is not reached from here: the engine reads it.
//! What comes back is untrusted: the engine judges the signatures.

use crate::net::pool::Pool;
use crate::registry::RegistryService;
use base64::Engine;
use std::sync::Arc;
use velarx_content::fetcher::fetch::{FetcherError, SignedRecord};
use velarx_registry::target::MAX_MANIFEST_SIZE;
use velarx_signature::reference::DockerRef;
use velarx_signature::registries_d::{self, RegistriesD};
use velarx_signature::sigstore::{Signature, Sigstore};
use velarx_types::digest::Digest;
use velarx_types::OciManifest;

/// Most layers of a sigstore attachment read.
const MAX_ATTACHMENTS: usize = 128;

fn failed(e: impl std::fmt::Display) -> FetcherError {
    FetcherError::failed(e.to_string())
}

fn bad(reason: impl Into<String>) -> FetcherError {
    FetcherError::InvalidArgument {
        reason: reason.into(),
    }
}

/// The signatures found so far, as the base64 of their blobs, and what is
/// left of the bytes they may take.
struct Found {
    blobs: Vec<String>,
    budget: u64,
}

impl Found {
    fn add(&mut self, blob: &[u8]) -> Result<(), FetcherError> {
        self.budget = self
            .budget
            .checked_sub(blob.len() as u64)
            .ok_or_else(|| failed("the signatures of the image are too large"))?;
        self.blobs
            .push(base64::engine::general_purpose::STANDARD.encode(blob));
        Ok(())
    }
}

/// The records of the signatures of the manifest the `reference`
/// (`NAME[:TAG]@DIGEST`) names, in `max` bytes at most once encoded.
pub(crate) async fn of(
    service: &RegistryService,
    pool: &Arc<Pool>,
    reference: &str,
    max: u64,
) -> Result<Vec<SignedRecord>, FetcherError> {
    let named = DockerRef::parse_normalized(reference).map_err(bad)?;
    let digest: Digest = named
        .digest
        .as_deref()
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| bad("the reference names no digest"))?;
    // (the scopes of registries.d are those of the name, with its tag)
    let named = DockerRef {
        digest: None,
        ..named
    };
    let config =
        RegistriesD::load_configured(service.pull.registries_d.as_deref()).map_err(failed)?;
    // (the base64 of what is found is a third larger)
    let mut found = Found {
        blobs: Vec::new(),
        budget: max / 2,
    };
    lookaside(service, &config, &named, &digest.to_string(), &mut found).await?;
    if config.use_sigstore_attachments(&named) {
        attachments(pool, &digest, &mut found).await?;
    }
    Ok(vec![SignedRecord {
        digest: digest.to_string(),
        platform: None,
        signatures: found.blobs,
    }])
}

/// The signatures of `digest` in the lookaside storage of `named`, if it is
/// on the network: `signature-1`, `signature-2`... up to the first that is
/// missing.
async fn lookaside(
    service: &RegistryService,
    config: &RegistriesD,
    named: &DockerRef,
    digest: &str,
    found: &mut Found,
) -> Result<(), FetcherError> {
    let base = config.lookaside_base(named, false).map_err(failed)?;
    if registries_d::file_path(&base).is_some() {
        return Ok(());
    }
    let fetcher = service.url_fetcher();
    for i in 0..registries_d::MAX_LOOKASIDE_SIGNATURES {
        let url = registries_d::lookaside_url(&base, digest, i).map_err(failed)?;
        let mut blob = Vec::new();
        let got = fetcher
            .fetch_opt(&url, found.budget, &mut |chunk| {
                blob.extend_from_slice(chunk);
                Ok(())
            })
            .await
            .map_err(|e| failed(format!("reading signature from {url}: {e}")))?;
        if got.is_none() {
            return Ok(());
        }
        found.add(&blob)?;
    }
    Err(failed(format!(
        "the signature storage has more than {} signatures of {digest}",
        registries_d::MAX_LOOKASIDE_SIGNATURES
    )))
}

/// The sigstore attachments of `digest`: the layers of the manifest tagged
/// `ALGO-HEX.sig` in the repository, if it has one.
async fn attachments(
    pool: &Arc<Pool>,
    digest: &Digest,
    found: &mut Found,
) -> Result<(), FetcherError> {
    let tag = format!("{}.sig", digest.to_string().replacen(':', "-", 1));
    let Some((body, _)) = pool
        .manifest_opt(&tag, MAX_MANIFEST_SIZE)
        .await
        .map_err(failed)?
    else {
        return Ok(());
    };
    let manifest: OciManifest = serde_json::from_slice(&body)
        .map_err(|e| failed(format!("invalid sigstore attachment manifest: {e}")))?;
    if manifest.layers.len() > MAX_ATTACHMENTS {
        return Err(failed("too many sigstore attachments"));
    }
    for layer in manifest.layers {
        let size = u64::try_from(layer.size)
            .ok()
            .filter(|&n| n <= found.budget)
            .ok_or_else(|| {
                failed(format!(
                    "the sigstore attachment {} is too large",
                    layer.digest
                ))
            })?;
        let mut payload = Vec::new();
        pool.blob(&layer.digest, size, &mut |chunk| {
            payload.extend_from_slice(chunk);
            Ok(())
        })
        .await
        .map_err(failed)?;
        if Digest::of(layer.digest.alg(), &payload) != layer.digest {
            return Err(failed(format!("{} is not what it says", layer.digest)));
        }
        let signature = Signature::Sigstore(Sigstore {
            mime_type: layer.media_type,
            payload,
            annotations: layer.annotations.into_iter().collect(),
        });
        found.add(&signature.to_blob())?;
    }
    Ok(())
}
