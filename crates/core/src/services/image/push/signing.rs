// SPDX-License-Identifier: Apache-2.0
//! The signatures of a push: made with the private key of the user, kept
//! where registries.d says for the destination, as containers/image does
//! (`copy --sign-by-sigstore-private-key`): the layers of the manifest
//! tagged `ALGO-HEX.sig` of the repository (sigstore attachments), or the
//! staging directory of the signature storage.

use super::*;
use velarx_signature::registries_d;
use velarx_signature::sign::Signer;
use velarx_signature::sigstore::{Sigstore, SIGSTORE_MEDIA_TYPE};

/// Where the signatures of a push go.
#[derive(Debug, Clone)]
pub(in crate::services::image) enum Sink {
    /// Sigstore attachments in the repository of the destination.
    Attachments,
    /// Files of the signature storage: the base URL of the repository.
    Staging(String),
}

/// The signature of a push: the key and how it names the image.
#[derive(Clone)]
pub(in crate::services::image) struct Signing {
    pub(in crate::services::image) signer: Arc<Signer>,
    pub(in crate::services::image) sink: Sink,
    /// The name the signatures give the image: what a policy compares the
    /// name a pull was asked by with.
    pub(in crate::services::image) identity: String,
}

/// The registry a push talks to: the connection, the worker and the access
/// that go together wherever a push makes a request.
#[derive(Clone, Copy)]
pub(super) struct Remote<'a> {
    pub(super) client: &'a Resolver,
    pub(super) staged: &'a Arc<StagedPush>,
    pub(super) worker: &'a PushWorker,
    pub(super) destination: &'a ImageReference,
    pub(super) tls_verify: bool,
    pub(super) access: &'a velarx_registry::auth::RegistryAccess,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn creator() -> String {
    format!("velarx {}", env!("CARGO_PKG_VERSION"))
}

impl ImageService {
    /// What signs a push to `destination`, decided before anything is
    /// uploaded: the key, and where registries.d has the signatures go.
    pub(in crate::services::image) fn signing_for(
        &self,
        signer: &Arc<Signer>,
        destination: &ImageReference,
        identity: Option<&str>,
    ) -> ImageResult<Signing> {
        let reference = super::super::signatures::intended(destination)?;
        let config = self.registries_config()?;
        let sink = if config.use_sigstore_attachments(&reference) {
            Sink::Attachments
        } else if config.lookaside(&reference, true).is_some() {
            let base = config
                .lookaside_base(&reference, true)
                .map_err(ImageError::Registry)?;
            if registries_d::file_path(&base).is_none() {
                return Err(ImageError::Registry(format!(
                    "pushing signatures to {base} is not supported: a signature storage to write to is a file: URL"
                )));
            }
            Sink::Staging(base)
        } else {
            return Err(ImageError::Registry(
                "Pushing signatures to a Docker Registry is not supported, and there is no applicable \
                 signature storage configured: set use-sigstore-attachments in registries.d"
                    .into(),
            ));
        };
        let identity = match identity {
            Some(i) => i.to_string(),
            None => {
                let mut named = destination.clone();
                named.digest = None;
                if named.tag.is_none() {
                    named.tag = Some("latest".into());
                }
                super::super::signatures::intended(&named)?.string()
            }
        };
        Ok(Signing {
            signer: signer.clone(),
            sink,
            identity,
        })
    }

    /// Refuse to sign a manifest that is not named by a sha256: the
    /// signature code names manifests, and builds the tag of the attachment,
    /// by sha256 only.
    pub(in crate::services::image) fn check_signable(digest: &Digest) -> ImageResult<()> {
        if digest.alg() != Algorithm::Sha256 {
            return Err(ImageError::Invalid(format!(
                "signing an image with a {} manifest digest is not supported yet",
                digest.alg()
            )));
        }
        Ok(())
    }

    /// Sign the manifest `digest` just pushed to the destination of `remote`.
    pub(super) async fn sign_pushed(
        &self,
        signing: &Signing,
        remote: &Remote<'_>,
        digest: Digest,
    ) -> ImageResult<()> {
        Self::check_signable(&digest)?;
        let text = digest.to_string();
        let signature = signing
            .signer
            .sign_manifest(&text, &signing.identity, &creator(), now())
            .map_err(|e| ImageError::Registry(format!("signing {digest}: {e}")))?;
        match &signing.sink {
            Sink::Staging(base) => write_staged(base, &text, &signature),
            Sink::Attachments => self.attach(remote, digest, signature).await,
        }
    }

    /// Sign the manifest `digest` that is in the repository of
    /// `destination` already.
    pub(in crate::services::image) async fn sign_digest(
        &self,
        signing: &Signing,
        destination: &ImageReference,
        digest: Digest,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<()> {
        let client = self
            .resolver
            .with_tls_verify(tls_verify)
            .with_access(access);
        // (refuses a blocked registry or a name that is not valid)
        client.push_target(destination)?;
        let staged = self
            .staged_push(&client, destination, tls_verify, access, None)
            .await?;
        let worker = self.push_worker(None);
        let remote = Remote {
            client: &client,
            staged: &staged,
            worker: &worker,
            destination,
            tls_verify,
            access,
        };
        self.sign_pushed(signing, &remote, digest).await?;
        staged.finish().await
    }

    /// Add `signature` to the sigstore attachment manifest of `digest`.
    async fn attach(
        &self,
        remote: &Remote<'_>,
        digest: Digest,
        signature: Sigstore,
    ) -> ImageResult<()> {
        let Remote {
            client,
            staged,
            worker,
            destination,
            tls_verify,
            access,
        } = *remote;
        let tag = format!("{}-{}.sig", digest.alg(), digest.hex());
        destination.validate()?;
        let reader = self.inspect_net(client, destination, tls_verify, access)?;
        let mut layers = match reader.manifest_opt(&tag).await? {
            Some((body, _)) => {
                serde_json::from_slice::<OciManifest>(&body)
                    .map_err(|e| {
                        ImageError::Registry(format!("invalid sigstore attachment manifest: {e}"))
                    })?
                    .layers
            }
            None => Vec::new(),
        };
        let payload = Bytes::from(signature.payload);
        let payload_digest = Digest::of(Algorithm::Sha256, &payload);
        let annotations: HashMap<String, String> = signature.annotations.into_iter().collect();
        let known = layers.iter().any(|l| {
            l.digest == payload_digest
                && l.media_type == SIGSTORE_MEDIA_TYPE
                && l.annotations == annotations
        });
        if !known {
            let object = worker.object(
                &payload_digest,
                payload.len() as u64,
                SIGSTORE_MEDIA_TYPE,
                Role::Blob,
                Vec::new(),
            );
            worker
                .ensure(
                    staged,
                    (&payload_digest, &object),
                    Source::Bytes(payload.clone()),
                    true,
                )
                .await?;
            layers.push(OciDescriptor {
                media_type: SIGSTORE_MEDIA_TYPE.to_string(),
                digest: payload_digest,
                size: payload.len() as i64,
                annotations,
            });
        }
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": "",
            "os": "",
            "rootfs": {
                "type": "layers",
                "diff_ids": layers.iter().map(|l| l.digest.to_string()).collect::<Vec<_>>(),
            },
        }))?;
        let config = Bytes::from(config);
        let config_digest = Digest::of(Algorithm::Sha256, &config);
        let config_object = worker.object(
            &config_digest,
            config.len() as u64,
            OCI_CONFIG,
            Role::Config,
            Vec::new(),
        );
        worker
            .ensure(
                staged,
                (&config_digest, &config_object),
                Source::Bytes(config.clone()),
                true,
            )
            .await?;
        let manifest = OciManifest {
            schema_version: 2,
            media_type: Some(OCI_MANIFEST.to_string()),
            config: OciDescriptor {
                media_type: OCI_CONFIG.to_string(),
                digest: config_digest,
                size: config.len() as i64,
                annotations: HashMap::new(),
            },
            layers,
            annotations: HashMap::new(),
        };
        super::put_manifest_as(
            staged,
            &tag,
            OCI_MANIFEST,
            &serde_json::to_vec(&manifest)?,
            Algorithm::Sha256,
        )
        .await?;
        Ok(())
    }
}

/// Write `signature` as the first `signature-N` of `digest` that is not
/// in the storage `base` (a `file:` URL of the repository).
fn write_staged(base: &str, digest: &str, signature: &Sigstore) -> ImageResult<()> {
    let blob = velarx_signature::sigstore::Signature::Sigstore(signature.clone()).to_blob();
    registries_d::write_lookaside(base, digest, &blob).map_err(ImageError::Registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest named by a sha512 is refused by name; a sha256 one signs.
    #[test]
    fn only_a_manifest_named_by_a_sha256_is_signed() {
        assert!(ImageService::check_signable(&Digest::of(Algorithm::Sha256, b"m")).is_ok());
        let e = ImageService::check_signable(&Digest::of(Algorithm::Sha512, b"m"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            "signing an image with a sha512 manifest digest is not supported yet"
        );
    }
}
