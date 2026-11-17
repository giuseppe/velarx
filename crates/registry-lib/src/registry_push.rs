// SPDX-License-Identifier: Apache-2.0
//! The registry as a pusher (`org.velarx.Pusher`): what `velarx-registry`
//! places at the repository of the scope.  It owns its destination: `Probe`
//! asks the registry whether it has a blob (a HEAD) and mounts it from the
//! repositories the engine says have it, `Put` uploads in pieces and tells
//! the bytes the registry has taken, `Commit` puts the manifest by each tag
//! and, for a digest that is not a sha256, by its digest too.  It reads
//! only the data files it is handed and the credentials of its scope.

use crate::net::pool::Pool;
use crate::registry::{upload_file, Reach, RegistryService, Tell};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;
use velarx_content::pusher::push::{
    CommitReply, EventKind, Have, Object, Placed, Probed, PusherError, PutEvent,
};
use velarx_content::serve_fetch::{Described, Out};
use velarx_content::serve_push::{CommitCall, PushScope, Pushing, PutCall};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::ImageError;

/// The words of its `GetInfo`.
const CAPABILITIES: [&str; 4] = ["origin", "link", "parallel", "sha512"];

/// The objects of one `Put` or `Probe` of the registry.
const MAX_OBJECTS: u32 = 15;

/// The registry that is the destination of a scope.
pub struct RegistryPush {
    service: Arc<RegistryService>,
}

impl RegistryPush {
    pub fn new(service: Arc<RegistryService>) -> Arc<Self> {
        Arc::new(Self { service })
    }

    /// The workers of the scope's repository: made at its first call, kept
    /// with the scope (new credentials make a new scope).
    fn pool(&self, scope: &PushScope) -> Result<Arc<Pool>, PusherError> {
        if let Some(kept) = scope.kept.get() {
            if let Some(pool) = kept.downcast_ref::<Arc<Pool>>() {
                return Ok(pool.clone());
            }
        }
        let (pool, _) = self
            .service
            .pool_for(
                &scope.destination,
                scope.tls_verify.unwrap_or(true),
                scope.access.as_deref().map(Vec::as_slice),
                Reach::Push,
            )
            .map_err(|e| PusherError::failed(e.to_string()))?;
        // (two calls made it at once: the first stays)
        let kept = scope
            .kept
            .get_or_init(|| -> Arc<dyn std::any::Any + Send + Sync> { Arc::new(pool.clone()) });
        Ok(kept.downcast_ref::<Arc<Pool>>().cloned().unwrap_or(pool))
    }
}

fn digest_of(object: &Object) -> Result<Digest, PusherError> {
    object
        .digest
        .parse()
        .map_err(|_| PusherError::InvalidArgument {
            reason: "not a digest".into(),
        })
}

/// What the registry answered, as the failure of the call: the one place
/// where the class of an error of the registry client is decided.
fn refused(_destination: &str, e: &ImageError) -> PusherError {
    PusherError::Failed {
        failure: crate::registry_fetch::registry_failure(e),
    }
}

/// Whether the error is a registry's refusal of a manifest put (a 4xx
/// answer).
fn refused_by_registry(e: &ImageError) -> bool {
    e.to_string().contains("Failed to push manifest: 4")
}

/// What the registry answered, from the text of its refusal.
fn refusal_text(e: &ImageError) -> String {
    let text = e.to_string();
    let text = text
        .split_once("Failed to push manifest: ")
        .map_or(text.as_str(), |(_, answer)| answer);
    // (without the hint for a tag push, said in the warning's own words)
    let text = text.split(" (the registry may not").next().unwrap_or(text);
    text.trim().chars().take(300).collect()
}

/// The blobs a registry says a manifest names that it does not have
/// (`MANIFEST_BLOB_UNKNOWN`, with the digest in its detail).
fn unknown_blobs(e: &ImageError) -> Vec<String> {
    let text = e.to_string();
    let Some(body) = text.split_once(" - ").map(|(_, b)| b) else {
        return Vec::new();
    };
    let Some(json) = body.find('{').map(|at| &body[at..]) else {
        return Vec::new();
    };
    let Ok(answer) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    answer["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["code"] == "MANIFEST_BLOB_UNKNOWN")
        .filter_map(|e| {
            e["detail"]["digest"]
                .as_str()
                .or_else(|| e["detail"].as_str())
        })
        .filter(|d| d.parse::<Digest>().is_ok())
        .map(str::to_string)
        .collect()
}

#[async_trait]
impl Pushing for RegistryPush {
    fn described(&self) -> Described {
        Described {
            name: "registry".into(),
            capabilities: CAPABILITIES.map(String::from).to_vec(),
            max_objects: MAX_OBJECTS,
        }
    }

    async fn probe(
        &self,
        scope: &PushScope,
        objects: Vec<Object>,
        out: &Out<Probed>,
    ) -> Result<(), PusherError> {
        let pool = self.pool(scope)?;
        let said = |index: usize, have: Have| Probed {
            index: index as u32,
            have,
            failure: None,
        };
        for (index, object) in objects.iter().enumerate() {
            let digest = digest_of(object)?;
            let fail = |e: ImageError| refused(&scope.destination, &e);
            let have = if pool.blob_exists(&digest).await.map_err(fail)? {
                Have::Present
            } else {
                let mut linked = false;
                for from in object.known_at.iter().flatten() {
                    if pool.mount(&digest, from).await.map_err(fail)? {
                        // (registry:3 answers 201 to the mount of a blob by a
                        // sha512 and does not link it: it is looked for, and
                        // it is not linked if it is not there)
                        linked = digest.alg() == Algorithm::Sha256
                            || pool.blob_exists(&digest).await.map_err(fail)?;
                        if !linked {
                            debug!("Blob {digest} was not mounted from {from}: the registry says it did");
                        }
                        break;
                    }
                }
                if linked {
                    Have::Linked
                } else {
                    Have::Needed
                }
            };
            out.send(said(index, have))
                .await
                .map_err(|_| PusherError::failed("the asker is gone"))?;
        }
        Ok(())
    }

    async fn put(
        &self,
        scope: &PushScope,
        call: PutCall,
        out: &Out<PutEvent>,
    ) -> Result<(), PusherError> {
        let pool = self.pool(scope)?;
        let chunk = self.service.push.chunk_mib.clamp(1, 1024) * 1024 * 1024;
        let gone = |_| PusherError::failed("the asker is gone");
        for (index, (object, data)) in call.objects.iter().zip(call.data).enumerate() {
            let at = vec![index as u32];
            let digest = digest_of(object)?;
            let progress = out.clone();
            let tell: Tell = {
                let at = at.clone();
                Arc::new(move |sent| {
                    let (progress, at) = (progress.clone(), at.clone());
                    Box::pin(async move {
                        let _ = progress
                            .send(PutEvent {
                                objects: at,
                                bytes: Some(sent),
                                ..PutEvent::of(EventKind::Progress)
                            })
                            .await;
                    })
                })
            };
            let done = tokio::select! {
                done = upload_file(&pool, &digest, (object.size, chunk), data, tell) => done,
                () = call.cancel.cancelled() => return Ok(()),
            };
            let event = match done {
                Ok(()) => PutEvent {
                    objects: at,
                    ..PutEvent::of(EventKind::Placed)
                },
                Err(e) => PutEvent::failed(at, crate::registry_fetch::registry_failure(&e)),
            };
            out.send(event).await.map_err(gone)?;
        }
        Ok(())
    }

    async fn commit(
        &self,
        scope: &PushScope,
        call: CommitCall,
    ) -> Result<CommitReply, PusherError> {
        let pool = self.pool(scope)?;
        let ours = digest_of(&call.manifest)?;
        let alg = ours.alg();
        let body = bytes::Bytes::from(call.body);
        if Digest::of(alg, &body) != ours {
            return Err(PusherError::InvalidArgument {
                reason: "the manifest is not the digest the call says".into(),
            });
        }
        // (a manifest with no tag is put by its digest)
        let digest_name = ours.to_string();
        let names = if call.names.is_empty() {
            vec![digest_name.clone()]
        } else {
            call.names.clone()
        };
        let put = |reference: String| {
            let (pool, body) = (pool.clone(), body.clone());
            let media = call.manifest.media_type.clone();
            async move {
                let got = pool
                    .put_manifest(&reference, &media, body.clone(), alg)
                    .await?;
                // the registry names what it has by the digest of the bytes
                if got == ours || (got.alg() != alg && got.verify(&body)) {
                    Ok(())
                } else {
                    Err(ImageError::DigestMismatch {
                        expected: ours.to_string(),
                        actual: got.to_string(),
                    })
                }
            }
        };
        for name in &call.names {
            velarx_content::serve_push::checked_tag(name)?;
        }
        for name in &names {
            put(name.clone()).await.map_err(|e| {
                let unknown = unknown_blobs(&e);
                if unknown.is_empty() {
                    refused(&scope.destination, &e)
                } else {
                    PusherError::ObjectsMissing { digests: unknown }
                }
            })?;
        }
        // (a registry names a manifest put by a tag with the sha256 of its
        // bytes, and the name `NAME@sha512:D` is the one velarx shows: the
        // `?digest=` of a manifest put is no part of the distribution spec,
        // so it is a second put; a registry that refuses it keeps the tag)
        let accepted = |name: Option<String>| Placed {
            name,
            accepted: true,
            reason: None,
        };
        let mut placed: Vec<Placed> = call
            .names
            .iter()
            .cloned()
            .map(|n| accepted(Some(n)))
            .collect();
        if alg != Algorithm::Sha256 && !call.names.is_empty() {
            match put(digest_name).await {
                Ok(()) => placed.push(accepted(None)),
                Err(e) if refused_by_registry(&e) => placed.push(Placed {
                    name: None,
                    accepted: false,
                    reason: Some(refusal_text(&e)),
                }),
                Err(e) => return Err(refused(&scope.destination, &e)),
            }
        } else {
            // (a name put by a tag, or by the digest itself, has the digest)
            placed.push(accepted(None));
        }
        Ok(CommitReply {
            digest: ours.to_string(),
            placed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_with(body: &str) -> ImageError {
        ImageError::Registry(format!("Failed to push manifest: 404 Not Found - {body}"))
    }

    /// The registry's `MANIFEST_BLOB_UNKNOWN` names the blobs it lacks; any
    /// other refusal names none.
    #[test]
    fn the_blobs_a_registry_lacks_are_the_digests_of_its_answer() {
        let a = crate::sha256(b"a").to_string();
        let b = crate::sha256(b"b").to_string();
        let body = format!(
            r#"{{"errors":[{{"code":"MANIFEST_BLOB_UNKNOWN","detail":{{"digest":"{a}"}}}},{{"code":"MANIFEST_BLOB_UNKNOWN","detail":"{b}"}}]}}"#
        );
        assert_eq!(unknown_blobs(&failed_with(&body)), [a, b]);
        assert!(
            unknown_blobs(&failed_with(r#"{"errors":[{"code":"DIGEST_INVALID"}]}"#)).is_empty()
        );
        assert!(unknown_blobs(&failed_with("not json")).is_empty());
        assert!(unknown_blobs(&ImageError::Registry("other".into())).is_empty());
    }

    #[test]
    fn only_a_4xx_answer_is_a_refusal() {
        let e = ImageError::Registry("Failed to push manifest: 503 Service Unavailable - x".into());
        assert!(!refused_by_registry(&e));
        let e = ImageError::Registry("Failed to push manifest: 400 Bad Request - x".into());
        assert!(refused_by_registry(&e));
        assert_eq!(refusal_text(&e), "400 Bad Request - x");
    }
}
