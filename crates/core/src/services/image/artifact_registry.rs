// SPDX-License-Identifier: Apache-2.0
//! Pulls and pushes of OCI artifacts: the registry access of the
//! images (policy, credentials, confined workers), the store of
//! `services::artifact`.

use super::push::Source;
use super::*;
use crate::services::artifact::{normalize_name, ArtifactError, ArtifactStore};
use bytes::Bytes;
use serde_json::Value;
use std::sync::Arc;
use velarx_content::pusher::push::Role;

fn store_error(e: ArtifactError) -> ImageError {
    match e {
        ArtifactError::NotFound(n) => ImageError::NotFound(n),
        ArtifactError::Io(e) => ImageError::Io(e),
        e => ImageError::Storage(e.to_string()),
    }
}

/// The descriptors of the blobs a manifest needs: its config (unless the
/// manifest carries it as data) and its layers.
fn blobs_of(manifest: &Value) -> ImageResult<Vec<(Digest, u64)>> {
    let mut out = Vec::new();
    let config = &manifest["config"];
    let mut descs: Vec<&Value> = Vec::new();
    if config.is_object() && config.get("data").is_none() {
        descs.push(config);
    }
    descs.extend(manifest["layers"].as_array().into_iter().flatten());
    for d in descs {
        let digest: Digest = d["digest"]
            .as_str()
            .ok_or_else(|| ImageError::Manifest("a descriptor without a digest".into()))?
            .parse()
            .map_err(|e| {
                ImageError::Manifest(format!("a descriptor without a valid digest: {e}"))
            })?;
        let size = d["size"].as_u64().ok_or_else(|| {
            ImageError::Manifest(format!("the descriptor of {digest} has no size"))
        })?;
        out.push((digest, size));
    }
    Ok(out)
}

impl ImageService {
    /// Pull the artifact `reference` (a tag) into `store`: the digest of
    /// its manifest.
    pub async fn pull_oci_artifact(
        &self,
        store: Arc<ArtifactStore>,
        reference: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Digest> {
        let image_ref = ImageReference::parse(reference)?;
        if image_ref.digest.is_some() {
            return Err(ImageError::Registry(format!(
                "{reference}: an artifact is pulled by its tag"
            )));
        }
        image_ref.validate()?;
        self.check_policy(&image_ref)?;
        let name = normalize_name(reference).map_err(store_error)?;
        image_ref.validate()?;
        let net = self.inspect_net(&image_ref, tls_verify, access)?;
        let tag = image_ref.tag.clone().unwrap_or_else(|| "latest".into());
        let (bytes, digest) = net.manifest_top(&tag).await?;
        let manifest: Value = serde_json::from_slice(&bytes)?;
        let media_type = manifest["mediaType"].as_str().unwrap_or_default();
        if manifest.get("manifests").is_some()
            || media_type.contains("index")
            || media_type.contains("list")
        {
            return Err(ImageError::Manifest(format!(
                "{reference} is an index: artifacts are single manifests"
            )));
        }
        for (blob, size) in blobs_of(&manifest)? {
            if store.has_blob(&blob) {
                continue;
            }
            let w = {
                let s = store.clone();
                tokio::task::spawn_blocking(move || s.begin_blob())
                    .await
                    .map_err(std::io::Error::other)?
                    .map_err(store_error)?
            };
            net.blob(&blob, size, w.file()).await?;
            let s = store.clone();
            tokio::task::spawn_blocking(move || s.finish_blob(w, &blob))
                .await
                .map_err(std::io::Error::other)?
                .map_err(store_error)?;
        }
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.put_pulled(&name, &digest, &bytes))
            .await
            .map_err(std::io::Error::other)?
            .map_err(store_error)
    }

    /// Push the artifact `name` of `store` to `destination` (else its own
    /// name): the digest of the manifest pushed, and how the destination
    /// resolves it.
    pub async fn push_oci_artifact(
        &self,
        store: Arc<ArtifactStore>,
        name: &str,
        destination: Option<&str>,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<(Digest, Vec<velarx_proto::transfer::Placed>)> {
        let (artifact, bytes) = {
            let s = store.clone();
            let n = name.to_string();
            tokio::task::spawn_blocking(move || {
                let a = s.get(&n)?;
                let b = s.manifest_bytes(&a)?;
                Ok::<_, ArtifactError>((a, b))
            })
            .await
            .map_err(std::io::Error::other)?
            .map_err(store_error)?
        };
        let dest = destination.unwrap_or(&artifact.name);
        let dest_ref = ImageReference::parse(dest)?;
        if dest_ref.digest.is_some() {
            return Err(ImageError::Registry(format!(
                "{dest}: an artifact is pushed to a tag"
            )));
        }
        dest_ref.validate()?;
        let client = self
            .resolver
            .with_tls_verify(tls_verify)
            .with_access(access);
        // (refuses a blocked registry or a name that is not valid)
        client.push_target(&dest_ref)?;
        let staged = self
            .staged_push(&dest_ref, tls_verify, access, None)
            .await?;
        let worker = self.push_worker(None);
        // the config too, even one the manifest carries as data: the
        // registry checks that it has every blob of a manifest
        let mut blobs = blobs_of(&artifact.manifest)?;
        let config = &artifact.manifest["config"];
        if let (Some(d), Some(size), Some(data)) = (
            config["digest"].as_str(),
            config["size"].as_u64(),
            config["data"].as_str(),
        ) {
            let d: Digest = d
                .parse()
                .map_err(|e| ImageError::Manifest(format!("the digest of the config: {e}")))?;
            let d = &d;
            let object = worker.object(
                d,
                size,
                config["mediaType"].as_str().unwrap_or(""),
                Role::Config,
                Vec::new(),
            );
            if worker.find(&staged, &object).await?.is_none() {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| ImageError::Manifest(format!("the data of the config: {e}")))?;
                let check = Digest::of(d.alg(), &bytes);
                if check != *d || bytes.len() as u64 != size {
                    return Err(ImageError::DigestMismatch {
                        expected: d.to_string(),
                        actual: check.to_string(),
                    });
                }
                worker
                    .ensure(
                        &staged,
                        (d, &object),
                        Source::Bytes(Bytes::from(bytes)),
                        false,
                    )
                    .await?;
            }
            blobs.retain(|(b, _)| b != d);
        }
        for (blob, size) in blobs {
            let object = worker.object(&blob, size, "", Role::Blob, Vec::new());
            if worker.find(&staged, &object).await?.is_some() {
                continue;
            }
            let file = Arc::new(store.open_blob(&blob, size).map_err(store_error)?);
            worker
                .ensure(&staged, (&blob, &object), Source::File(file, size), false)
                .await?;
        }
        let tag = dest_ref.tag.clone().unwrap_or_else(|| "latest".into());
        let media_type = artifact.manifest["mediaType"]
            .as_str()
            .unwrap_or(crate::services::artifact::MANIFEST_MEDIA_TYPE)
            .to_string();
        let (pushed, placed) =
            super::push::put_manifest_as(&staged, &tag, &media_type, &bytes, artifact.digest.alg())
                .await?;
        staged.finish().await?;
        if pushed != artifact.digest {
            return Err(ImageError::DigestMismatch {
                expected: artifact.digest.to_string(),
                actual: pushed.to_string(),
            });
        }
        Ok((pushed, placed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_blobs_of_a_manifest() {
        let d = "sha256:".to_string() + &"a".repeat(64);
        let m = json!({
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": d, "size": 2, "data": "e30="},
            "layers": [{"digest": d, "size": 5}],
        });
        let parsed: Digest = d.parse().unwrap();
        assert_eq!(blobs_of(&m).unwrap(), vec![(parsed, 5)]);
        let m = json!({"config": {"digest": d, "size": 2}, "layers": []});
        assert_eq!(blobs_of(&m).unwrap(), vec![(parsed, 2)]);
        let d512 = format!("sha512:{}", "b".repeat(128));
        let m = json!({"layers": [{"digest": d512, "size": 3}]});
        assert_eq!(blobs_of(&m).unwrap(), vec![(d512.parse().unwrap(), 3)]);
        assert!(blobs_of(&json!({"layers": [{"digest": "sha256:../x", "size": 1}]})).is_err());
        assert!(blobs_of(&json!({"layers": [{"digest": d}]})).is_err());
    }
}
