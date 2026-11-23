// SPDX-License-Identifier: Apache-2.0
//! Whether the requirements of policy.json accept an image, as
//! containers/image's `IsRunningImageAllowed`: every requirement must,
//! and a signature requirement accepts the image when one of its
//! signatures is valid, by a trusted key, for the manifest and for the
//! reference the image was asked by.

use super::openpgp;
use super::policy::{FulcioConfig, KeyType, PkiConfig, PolicyRequirement};
use super::reference::{DockerRef, SignedIdentity};
use super::sigstore::{self, Signature, TrustRoot};
use base64::Engine;

/// Largest key, keyring or certificate file read.
const MAX_KEY_FILE: u64 = 4 << 20;

/// What the signatures are judged for.
#[derive(Clone, Copy)]
pub enum Manifest<'a> {
    /// The bytes of the manifest (of the platform's manifest of an index).
    Bytes(&'a [u8]),
    /// Its digest, when the bytes are not there yet: the signatures name
    /// the digest, and the bytes are judged by it later.
    Digest(&'a str),
}

impl Manifest<'_> {
    fn has_digest(&self, digest: &str) -> bool {
        match self {
            Manifest::Bytes(bytes) => sigstore::manifest_matches(bytes, digest),
            Manifest::Digest(d) => *d == digest,
        }
    }
}

/// An image as the requirements see it.
pub struct Image<'a> {
    /// The reference it was asked by.
    pub reference: &'a DockerRef,
    pub manifest: Manifest<'a>,
    /// The signatures found for that manifest.
    pub signatures: &'a [Signature],
}

/// The reason of a refusal when there is no signature to check (the text of
/// containers/image).
pub const NO_SIGNATURE: &str = "a signature was required, but no signature exists";

/// Whether any of `requirements` needs the signatures of the image.
pub fn needs_signatures(requirements: &[PolicyRequirement]) -> bool {
    requirements.iter().any(|r| {
        matches!(
            r,
            PolicyRequirement::SignedBy { .. } | PolicyRequirement::SigstoreSigned { .. }
        )
    })
}

/// The signature requirements of `requirements` only (signedBy,
/// sigstoreSigned).
pub fn signature_requirements(requirements: &[PolicyRequirement]) -> Vec<PolicyRequirement> {
    requirements
        .iter()
        .filter(|r| needs_signatures(std::slice::from_ref(*r)))
        .cloned()
        .collect()
}

/// Ok when every requirement accepts `image` at `now` (seconds since the
/// epoch); else why one does not.
#[cfg(test)]
fn allows(requirements: &[PolicyRequirement], image: &Image, now: i64) -> Result<(), String> {
    accepted(requirements, image, now).map(|_| ())
}

/// Like `allows`, with the indexes in `image.signatures` of the signatures
/// that satisfied the signature requirements.
pub fn accepted(
    requirements: &[PolicyRequirement],
    image: &Image,
    now: i64,
) -> Result<Vec<usize>, String> {
    accepted_at(requirements, image, now).map(|(used, _)| used)
}

/// Like `accepted`, with when the image was signed: for each requirement
/// its newest signature, and of those the oldest time (0 when none needs
/// a signature).
pub fn accepted_at(
    requirements: &[PolicyRequirement],
    image: &Image,
    now: i64,
) -> Result<(Vec<usize>, i64), String> {
    if requirements.is_empty() {
        return Err("no requirement applies".into());
    }
    let mut used: Vec<(usize, i64)> = Vec::new();
    for r in requirements {
        match r {
            PolicyRequirement::InsecureAcceptAnything => {}
            PolicyRequirement::Reject => {
                return Err(format!(
                    "{} is rejected by policy",
                    image.reference.string()
                ))
            }
            PolicyRequirement::SignedBaseLayer { .. } => {
                return Err("signedBaseLayer requirements are not implemented".into())
            }
            PolicyRequirement::SignedBy {
                key_type,
                key_path,
                key_paths,
                key_data,
                signed_identity,
            } => used.push(signed_by(
                *key_type,
                key_path.as_deref(),
                key_paths.as_deref(),
                key_data.as_deref(),
                signed_identity.as_ref(),
                image,
                now,
            )?),
            PolicyRequirement::SigstoreSigned {
                key_path,
                key_paths,
                key_data,
                key_datas,
                fulcio,
                rekor_public_key_path,
                rekor_public_key_paths,
                rekor_public_key_data,
                rekor_public_key_datas,
                pki,
                signed_identity,
            } => {
                let root = (|| -> Result<TrustRoot, String> {
                    let keys = sources(
                        key_path.as_deref(),
                        key_paths.as_deref(),
                        key_data.as_deref(),
                        key_datas.as_deref(),
                    )?;
                    let rekor = sources(
                        rekor_public_key_path.as_deref(),
                        rekor_public_key_paths.as_deref(),
                        rekor_public_key_data.as_deref(),
                        rekor_public_key_datas.as_deref(),
                    )?;
                    Ok(TrustRoot {
                        public_keys: keys
                            .iter()
                            .map(|k| sigstore::public_key_from_pem(k).map_err(|e| e.0))
                            .collect::<Result<_, _>>()?,
                        fulcio: fulcio.as_deref().map(fulcio_root).transpose()?,
                        rekor_keys: rekor
                            .iter()
                            .map(|k| sigstore::public_key_from_pem(k).map_err(|e| e.0))
                            .collect::<Result<_, _>>()?,
                        pki: pki.as_deref().map(pki_root).transpose()?,
                    })
                })()?;
                root.check().map_err(|e| e.0)?;
                used.push(sigstore_signed(
                    &root,
                    signed_identity.as_ref(),
                    image,
                    now,
                )?)
            }
        }
    }
    let signed = used.iter().map(|(_, t)| *t).min().unwrap_or(0);
    let mut used: Vec<usize> = used.into_iter().map(|(i, _)| i).collect();
    used.sort_unstable();
    used.dedup();
    Ok((used, signed))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    velarx_base::conf::read_bounded(std::path::Path::new(path), MAX_KEY_FILE)
        .map_err(|e| format!("{path}: {e}"))
}

fn unbase64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| "key data that is not base64".to_string())
}

/// The data of exactly one of a path, paths, data and datas; none for
/// none of them.
fn sources(
    path: Option<&str>,
    paths: Option<&[String]>,
    data: Option<&str>,
    datas: Option<&[String]>,
) -> Result<Vec<Vec<u8>>, String> {
    let n = usize::from(path.is_some())
        + usize::from(paths.is_some())
        + usize::from(data.is_some())
        + usize::from(datas.is_some());
    if n > 1 {
        return Err("more than one of a path, paths and data of keys".into());
    }
    if let Some(p) = path {
        return Ok(vec![read(p)?]);
    }
    if let Some(ps) = paths {
        return ps.iter().map(|p| read(p)).collect();
    }
    if let Some(d) = data {
        return Ok(vec![unbase64(d)?]);
    }
    if let Some(ds) = datas {
        return ds.iter().map(|d| unbase64(d)).collect();
    }
    Ok(Vec::new())
}

fn certificates(
    path: Option<&str>,
    data: Option<&str>,
    what: &str,
) -> Result<Vec<openssl::x509::X509>, String> {
    let pems = sources(path, None, data, None)?;
    let Some(pem) = pems.first() else {
        return Err(format!("no {what}"));
    };
    let certs = openssl::x509::X509::stack_from_pem(pem).map_err(|_| format!("invalid {what}"))?;
    if certs.is_empty() {
        return Err(format!("no {what}"));
    }
    Ok(certs)
}

fn fulcio_root(f: &FulcioConfig) -> Result<sigstore::Fulcio, String> {
    Ok(sigstore::Fulcio {
        ca: certificates(
            f.ca_path.as_deref(),
            f.ca_data.as_deref(),
            "Fulcio CA certificates",
        )?,
        oidc_issuer: f.oidc_issuer.clone().unwrap_or_default(),
        subject_email: f.subject_email.clone().unwrap_or_default(),
    })
}

fn pki_root(p: &PkiConfig) -> Result<sigstore::Pki, String> {
    let intermediates = if p.ca_intermediates_path.is_some() || p.ca_intermediates_data.is_some() {
        certificates(
            p.ca_intermediates_path.as_deref(),
            p.ca_intermediates_data.as_deref(),
            "PKI intermediate certificates",
        )?
    } else {
        Vec::new()
    };
    Ok(sigstore::Pki {
        roots: certificates(
            p.ca_roots_path.as_deref(),
            p.ca_roots_data.as_deref(),
            "PKI root certificates",
        )?,
        intermediates,
        subject_email: p.subject_email.clone(),
        subject_hostname: p.subject_hostname.clone(),
    })
}

/// The manifest and the reference of a verified payload must be the
/// image's.
fn check_payload(
    payload: &sigstore::Payload,
    identity: Option<&SignedIdentity>,
    image: &Image,
) -> Result<i64, String> {
    if !image.manifest.has_digest(&payload.manifest_digest) {
        return Err(format!(
            "signature for digest {} does not match",
            payload.manifest_digest
        ));
    }
    let identity = identity.cloned().unwrap_or_default();
    if !identity.matches(image.reference, &payload.docker_reference) {
        return Err(format!(
            "signature for identity {:?} is not accepted",
            payload.docker_reference
        ));
    }
    Ok(payload.timestamp)
}

/// The summary of the reasons the signatures were refused.
fn summary(rejections: Vec<String>, none: String) -> String {
    match rejections.len() {
        0 => none,
        1 => rejections.into_iter().next().unwrap_or_default(),
        _ => format!(
            "none of the signatures were accepted, reasons: {}",
            rejections.join("; ")
        ),
    }
}

fn signed_by(
    key_type: KeyType,
    path: Option<&str>,
    paths: Option<&[String]>,
    data: Option<&str>,
    identity: Option<&SignedIdentity>,
    image: &Image,
    now: i64,
) -> Result<(usize, i64), String> {
    if key_type != KeyType::GpgKeys {
        return Err(format!("unimplemented keyType {key_type:?}"));
    }
    let keyrings = sources(path, paths, data, None)?;
    if keyrings.is_empty() {
        return Err("not exactly one of keyPath, keyPaths and keyData".into());
    }
    let mut keys = Vec::new();
    for k in &keyrings {
        keys.extend(openpgp::parse_keyring(k).map_err(|e| e.0)?);
    }
    if keys.is_empty() {
        return Err("no public keys imported".into());
    }
    let (mut rejections, mut newest) = (Vec::new(), None);
    for (i, sig) in image.signatures.iter().enumerate() {
        let Signature::Simple(blob) = sig else {
            continue;
        };
        let result = openpgp::verify_message(&keys, blob, u64::try_from(now).unwrap_or(0))
            .map_err(|e| e.0)
            .and_then(|(content, _)| {
                sigstore::parse_payload(&content, sigstore::SIMPLE_SIGNING_TYPE).map_err(|e| e.0)
            })
            .and_then(|payload| check_payload(&payload, identity, image));
        match result {
            Ok(signed) if newest.is_none_or(|(_, t)| signed > t) => newest = Some((i, signed)),
            Ok(_) => {}
            Err(e) => rejections.push(e),
        }
    }
    newest.ok_or_else(|| summary(rejections, NO_SIGNATURE.into()))
}

fn sigstore_signed(
    root: &TrustRoot,
    identity: Option<&SignedIdentity>,
    image: &Image,
    now: i64,
) -> Result<(usize, i64), String> {
    let (mut rejections, mut newest) = (Vec::new(), None);
    let (mut others, mut attachments) = (0, 0);
    for (i, sig) in image.signatures.iter().enumerate() {
        let Signature::Sigstore(s) = sig else {
            others += 1;
            continue;
        };
        if s.mime_type != sigstore::SIGSTORE_MEDIA_TYPE {
            attachments += 1;
            continue;
        }
        let result = root
            .verify(s, now)
            .map_err(|e| e.0)
            .and_then(|payload| check_payload(&payload, identity, image));
        match result {
            Ok(signed) if newest.is_none_or(|(_, t)| signed > t) => newest = Some((i, signed)),
            Ok(_) => {}
            Err(e) => rejections.push(e),
        }
    }
    if let Some(newest) = newest {
        return Ok(newest);
    }
    let none = if others + attachments == 0 {
        NO_SIGNATURE.to_string()
    } else {
        format!("{NO_SIGNATURE} ({others} non-sigstore signatures, {attachments} sigstore non-signature attachments)")
    };
    Err(summary(rejections, none))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::tests::{ec_key, payload, signature};
    use crate::SignaturePolicy;

    #[test]
    fn a_fifo_is_refused_not_waited_for() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        velarx_base::testing::make_fifo(&fifo);
        let r =
            velarx_base::testing::returns_within(std::time::Duration::from_secs(10), move || {
                read(fifo.to_str().unwrap())
            });
        assert!(r.is_err());
    }

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signature/",
                $name
            ))
        };
    }

    const NOW: i64 = 1_791_739_600;

    fn reqs(json: &str) -> Vec<PolicyRequirement> {
        let p = SignaturePolicy::parse(&format!(r#"{{"default": {json}}}"#)).unwrap();
        p.default
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn gpg_signatures_are_checked_against_manifest_and_reference() {
        let r = reqs(&format!(
            r#"[{{"type": "signedBy", "keyType": "GPGKeys", "keyData": "{}"}}]"#,
            b64(fixture!("key-rsa.gpg"))
        ));
        assert!(needs_signatures(&r));
        let sigs = [Signature::Simple(fixture!("msg-rsa.sig").to_vec())];
        let reference = DockerRef::parse_normalized("localhost:5000/signed/image:v1").unwrap();
        // msg-rsa signs a digest no manifest has
        let image = Image {
            reference: &reference,
            manifest: Manifest::Bytes(b"{}"),
            signatures: &sigs,
        };
        let e = allows(&r, &image, NOW).unwrap_err();
        assert!(e.contains("does not match"), "{e}");
        // msg-rsa-manifest signs this manifest
        let good = [Signature::Simple(fixture!("msg-rsa-manifest.sig").to_vec())];
        let manifest = br#"{"schemaVersion":2}"#;
        allows(
            &r,
            &Image {
                reference: &reference,
                manifest: Manifest::Bytes(manifest),
                signatures: &good,
            },
            NOW,
        )
        .unwrap();
        // with another signature that does not verify first
        let mixed = [sigs[0].clone(), good[0].clone()];
        // only the signature that verified is reported, to be kept
        let used = accepted(
            &r,
            &Image {
                reference: &reference,
                manifest: Manifest::Bytes(manifest),
                signatures: &mixed,
            },
            NOW,
        )
        .unwrap();
        assert_eq!(used, vec![1]);
        allows(
            &r,
            &Image {
                reference: &reference,
                manifest: Manifest::Bytes(manifest),
                signatures: &mixed,
            },
            NOW,
        )
        .unwrap();
        let v2 = DockerRef::parse_normalized("localhost:5000/signed/image:v2").unwrap();
        assert!(allows(
            &r,
            &Image {
                reference: &v2,
                manifest: Manifest::Bytes(manifest),
                signatures: &good
            },
            NOW
        )
        .is_err());
        // no signature at all
        let none = Image {
            reference: &reference,
            manifest: Manifest::Bytes(b"{}"),
            signatures: &[],
        };
        assert!(allows(&r, &none, NOW)
            .unwrap_err()
            .contains("no signature exists"));
        // keys of another signer
        let other = reqs(&format!(
            r#"[{{"type": "signedBy", "keyType": "GPGKeys", "keyData": "{}"}}]"#,
            b64(fixture!("key-ed.gpg"))
        ));
        assert!(allows(&other, &image, NOW)
            .unwrap_err()
            .contains("no trusted key"));
    }

    fn sigstore_image<'a>(
        reference: &'a DockerRef,
        manifest: &'a [u8],
        sigs: &'a [Signature],
    ) -> Image<'a> {
        Image {
            reference,
            manifest: Manifest::Bytes(manifest),
            signatures: sigs,
        }
    }

    #[test]
    fn sigstore_signatures_are_checked_against_manifest_and_reference() {
        use crate::sigstore::tests::DIGEST;
        let key = ec_key();
        let r = reqs(&format!(
            r#"[{{"type": "sigstoreSigned", "keyData": "{}"}}]"#,
            b64(&key.public_key_to_pem().unwrap())
        ));
        // a manifest whose digest is DIGEST cannot be made: check with the
        // digest of a real manifest instead
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(openssl::sha::sha256(manifest)));
        let p = String::from_utf8(payload(sigstore::SIGSTORE_TYPE, "quay.io/a/b:v1"))
            .unwrap()
            .replace(DIGEST, &digest);
        let sigs = [Signature::Sigstore(signature(&key, p.as_bytes(), None))];
        let reference = DockerRef::parse_normalized("quay.io/a/b:v1").unwrap();
        allows(&r, &sigstore_image(&reference, manifest, &sigs), NOW).unwrap();
        // another tag, another manifest
        let v2 = DockerRef::parse_normalized("quay.io/a/b:v2").unwrap();
        assert!(allows(&r, &sigstore_image(&v2, manifest, &sigs), NOW)
            .unwrap_err()
            .contains("identity"));
        assert!(allows(&r, &sigstore_image(&reference, b"{}", &sigs), NOW)
            .unwrap_err()
            .contains("digest"));
        // matchRepository accepts the other tag
        let repo = reqs(&format!(
            r#"[{{"type": "sigstoreSigned", "keyData": "{}", "signedIdentity": {{"type": "matchRepository"}}}}]"#,
            b64(&key.public_key_to_pem().unwrap())
        ));
        allows(&repo, &sigstore_image(&v2, manifest, &sigs), NOW).unwrap();
        // every requirement must hold: a reject after it refuses
        let mut both = r.clone();
        both.push(PolicyRequirement::Reject);
        assert!(allows(&both, &sigstore_image(&reference, manifest, &sigs), NOW).is_err());
        // a simple signing signature does not satisfy sigstoreSigned
        let simple = [Signature::Simple(fixture!("msg-rsa.sig").to_vec())];
        let e = allows(&r, &sigstore_image(&reference, manifest, &simple), NOW).unwrap_err();
        assert!(e.contains("1 non-sigstore"), "{e}");
    }

    #[test]
    fn inconsistent_requirements_refuse() {
        let reference = DockerRef::parse_normalized("a:b").unwrap();
        let image = Image {
            reference: &reference,
            manifest: Manifest::Bytes(b"{}"),
            signatures: &[],
        };
        for json in [
            // two sources of keys
            r#"[{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/x", "keyData": "eA=="}]"#,
            // no keys
            r#"[{"type": "signedBy", "keyType": "GPGKeys"}]"#,
            r#"[{"type": "signedBy", "keyType": "X509Certificates", "keyData": "eA=="}]"#,
            r#"[{"type": "sigstoreSigned"}]"#,
            // Fulcio without Rekor
            r#"[{"type": "sigstoreSigned", "fulcio": {"caData": "eA==", "oidcIssuer": "i", "subjectEmail": "e"}}]"#,
            r#"[{"type": "signedBaseLayer", "baseLayerIdentity": {"type": "matchRepository"}}]"#,
            r#"[{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/nonexistent/key.gpg"}]"#,
        ] {
            assert!(allows(&reqs(json), &image, NOW).is_err(), "{json}");
        }
        assert!(allows(&[], &image, NOW).is_err());
        allows(
            &reqs(r#"[{"type": "insecureAcceptAnything"}]"#),
            &image,
            NOW,
        )
        .unwrap();
    }
}
