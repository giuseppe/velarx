// SPDX-License-Identifier: Apache-2.0
//! The network side of a pull: what the engine asks of the registries.
//!
//! The engine does not talk to a registry itself, it asks a [`Net`] for the
//! manifest, the configuration, ranges of a blob and layers.  The answers are
//! untrusted bytes in both cases, the engine checks every digest.

pub mod origin;

use bytes::Bytes;
use velarx_proto::transfer::FailureClass;
use velarx_registry::target::{resolve_manifest_chain, KnownManifests, Platform, MAX_CONFIG_SIZE};
use velarx_types::digest::Digest;
use velarx_types::{
    ImageError, ImageReference, ImageResult, OciConfig, OciDescriptor, OciManifest,
};

#[derive(Clone)]
pub enum Net {
    /// Requests are made by the registry fetcher, another process.
    Origin(origin::OriginNet),
    /// No request at all: what an image installed from an archive or a
    /// commit has (its blobs are local); a request is a bug, refused.
    Offline,
}

fn offline() -> ImageError {
    ImageError::transfer(
        "registry",
        FailureClass::Failed,
        "no registry is reachable for a local image",
    )
}

impl Net {
    pub fn offline() -> Self {
        Net::Offline
    }

    fn origin(&self) -> ImageResult<&origin::OriginNet> {
        match self {
            Net::Origin(origin) => Ok(origin),
            Net::Offline => Err(offline()),
        }
    }

    /// The manifest (or index) `reference` (a tag or a digest) names as
    /// the registry serves it, and its digest.
    pub async fn manifest_top(&self, reference: &str) -> ImageResult<(Bytes, Digest)> {
        let top = self.origin()?.manifest(reference).await?;
        velarx_types::docker::refuse_manifest(&top.0)?;
        Ok(top)
    }

    /// The index of the images of the origin of a path, as it serves it
    /// (`GetManifest("")`): untrusted bytes.
    pub async fn path_index(&self) -> ImageResult<Bytes> {
        self.origin()?.path_index().await
    }

    /// The records of the signatures of the manifest `digest` of the image
    /// `reference` (`NAME[:TAG]@DIGEST`) that the sources give (untrusted).
    pub async fn fetched_signatures(
        &self,
        reference: &str,
        digest: &Digest,
    ) -> ImageResult<Vec<crate::fetcher::fetch::SignedRecord>> {
        match self {
            Net::Origin(origin) => origin.fetched_signatures(reference, digest).await,
            Net::Offline => Ok(Vec::new()),
        }
    }

    /// The manifest `reference` names, None when the registry has none.
    pub async fn manifest_opt(&self, reference: &str) -> ImageResult<Option<(Bytes, Digest)>> {
        self.origin()?.manifest_opt(reference).await
    }

    /// The blob `digest` of `size` bytes as the registry of `target` has
    /// it, written into `file` (empty, open for reading and writing) by the
    /// fetcher, and measured: its size and digest are the ones given.  No
    /// blob is held in memory.
    pub async fn blob(&self, digest: &Digest, size: u64, file: &std::fs::File) -> ImageResult<()> {
        self.origin()?
            .blob_into(
                &crate::fetcher::fetch::Blob {
                    digest: digest.to_string(),
                    size,
                    media_type: "application/octet-stream".into(),
                    annotations: None,
                },
                file,
            )
            .await
    }

    /// The manifest `image_ref` names, resolved for `platform`, its digest
    /// and its bytes.  The instance an index names comes from `known` when
    /// it has it (see [`resolve_manifest_chain`]); the indexes it went through
    /// come last.
    pub async fn manifest_raw(
        &self,
        image_ref: &ImageReference,
        platform: Option<&Platform>,
        known: Option<KnownManifests<'_>>,
    ) -> ImageResult<(OciManifest, Digest, Bytes, Vec<(Digest, Bytes)>)> {
        let origin = self.origin()?;
        resolve_manifest_chain(image_ref, platform, known, |reference| async move {
            origin.manifest(&reference).await
        })
        .await
        .map_err(|e| match (e, &image_ref.digest) {
            // (only the registry, or a signed record from a source of
            // `[pull] names`, says what a tag names: the other sources serve
            // what a digest names)
            (ImageError::Transfer { party, object, mut failure }, None)
                if matches!(
                    failure.class,
                    FailureClass::Transient | FailureClass::Unavailable
                ) =>
            {
                failure.reason = format!(
                    "{} (a tag needs the registry, or a source of [pull] names; a pull by digest can take the image from the other sources)",
                    failure.reason
                );
                ImageError::Transfer { party, object, failure }
            }
            (e, _) => e,
        })
    }

    /// The configuration of an image and its bytes, checked against the
    /// descriptor.
    pub async fn config_raw(&self, desc: &OciDescriptor) -> ImageResult<(OciConfig, Bytes)> {
        let origin = self.origin()?;
        if desc.size < 0 || desc.size as u64 > MAX_CONFIG_SIZE {
            return Err(ImageError::transfer_of(
                origin.party(),
                desc.digest.to_string(),
                FailureClass::Invalid,
                format!(
                    "too large ({} bytes, at most {} are accepted)",
                    desc.size, MAX_CONFIG_SIZE
                ),
            ));
        }
        let body = origin
            .small_blob(
                &crate::fetcher::fetch::Blob {
                    digest: desc.digest.to_string(),
                    size: desc.size as u64,
                    media_type: desc.media_type.clone(),
                    annotations: None,
                },
                MAX_CONFIG_SIZE,
            )
            .await?;
        Ok((serde_json::from_slice(&body)?, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An image from an archive or a commit makes no request: the offline
    /// Net refuses them all.
    #[tokio::test]
    async fn offline_refuses_every_request() {
        let net = Net::offline();
        assert!(net.manifest_top("latest").await.is_err());
        let file = tempfile::tempfile().unwrap();
        assert!(net.blob(&crate::sha256(b"x"), 1, &file).await.is_err());
    }

    /// A tag is resolved by the registry only: a pull of one with no
    /// registry says so; a digest does not.
    #[tokio::test]
    async fn a_tag_without_a_registry_says_it_needs_one() {
        let net = Net::Origin(origin::OriginNet::of_transport(
            velarx_config::Reach::Socket("/nonexistent/velarx-registry.sock".into()),
            std::time::Duration::from_secs(5),
            "docker://example.com/a".into(),
            true,
        ));
        let digest = format!("@{}", crate::sha256(b"x"));
        for (name, said) in [(":latest", true), (digest.as_str(), false)] {
            let r = ImageReference::parse(&format!("example.com/a{name}")).unwrap();
            let e = net.manifest_raw(&r, None, None).await.unwrap_err();
            assert_eq!(
                e.to_string().contains("a tag needs the registry"),
                said,
                "{e}"
            );
        }
    }

    /// With `registry` out of the sources the registry fetcher is not
    /// asked at all: the error says so, for a tag and for a digest.
    #[tokio::test]
    async fn a_pull_without_the_registry_in_its_sources_does_not_ask_it() {
        // (a socket that would be an error of another kind if it were used)
        let net = Net::Origin(
            origin::OriginNet::of_transport(
                velarx_config::Reach::Socket("/nonexistent/velarx-registry.sock".into()),
                std::time::Duration::from_secs(5),
                "docker://example.com/a".into(),
                true,
            )
            .with_sources(Vec::new()),
        );
        let digest = format!("@{}", crate::sha256(b"x"));
        for name in [":latest", digest.as_str()] {
            let r = ImageReference::parse(&format!("example.com/a{name}")).unwrap();
            let e = net.manifest_raw(&r, None, None).await.unwrap_err();
            assert!(
                e.to_string()
                    .contains("`registry` is not one of the sources"),
                "{e}"
            );
        }
    }
}
