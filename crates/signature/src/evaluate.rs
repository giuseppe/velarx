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
use velarx_policy_core::{decide, Fact, Item, Outcome, Rule};
pub use velarx_policy_core::{Mode, Pre, Why};

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

/// What `requirements` say of an image before any signature is read, as
/// `mode` judges it.
pub fn precheck(mode: Mode, requirements: &[PolicyRequirement]) -> Pre {
    let kinds: Vec<Item> = requirements
        .iter()
        .map(|r| match r {
            PolicyRequirement::InsecureAcceptAnything => Item::AcceptAnything,
            PolicyRequirement::Reject => Item::Reject,
            PolicyRequirement::SignedBaseLayer { .. } => Item::Unimplemented,
            PolicyRequirement::SignedBy { .. } | PolicyRequirement::SigstoreSigned { .. } => {
                Item::Signed(Rule::Nothing, Vec::new())
            }
        })
        .collect();
    velarx_policy_core::precheck(mode, &kinds)
}

/// Whether the signatures matter to the image, as `mode` judges: false only
/// when the requirements accept it whatever they are (what refuses fails
/// closed, as a caller that fetches nothing must not take it as "no").
pub fn needs_signatures(mode: Mode, requirements: &[PolicyRequirement]) -> bool {
    !matches!(precheck(mode, requirements), Pre::Accept)
}

/// What a refusal before any signature is read says, to follow "the
/// signature policy" (containers/image does not implement `signedBaseLayer`
/// either).  `Empty`, `Unusable` and `NoSignature` cannot come from the
/// pre-check: a list is never empty here (the policy refuses it when it is
/// read), and whether a key is usable or a signature exists is known only
/// when the signatures are read.
pub fn refusal(why: Why) -> &'static str {
    match why {
        Why::Rejected => "rejects it",
        Why::Unimplemented => "has a signedBaseLayer requirement, which is not implemented",
        Why::NotSigned => "accepts it without a signature",
        Why::Empty => "has no requirement",
        Why::Unusable | Why::NoSignature => "has a requirement that is not satisfied",
    }
}

/// Ok when every requirement accepts `image` at `now` (seconds since the
/// epoch); else why one does not.
#[cfg(test)]
fn allows(requirements: &[PolicyRequirement], image: &Image, now: i64) -> Result<(), String> {
    accepted(Mode::Whole, requirements, image, now).map(|_| ())
}

/// Like `allows` as `mode` judges, with the indexes in `image.signatures`
/// of the signatures that satisfied the signature requirements.
pub fn accepted(
    mode: Mode,
    requirements: &[PolicyRequirement],
    image: &Image,
    now: i64,
) -> Result<Vec<usize>, String> {
    accepted_at(mode, requirements, image, now).map(|(used, _)| used)
}

/// What a signature requirement that cannot be used is, and why.
fn unusable(why: String) -> (Item, String) {
    (Item::Unusable, why)
}

/// Like `accepted`, with when the image was signed: for each requirement
/// its newest signature, and of those the oldest time (0 when none needs
/// a signature).
pub fn accepted_at(
    mode: Mode,
    requirements: &[PolicyRequirement],
    image: &Image,
    now: i64,
) -> Result<(Vec<usize>, i64), String> {
    // (with each requirement, why no signature satisfies it)
    let (mut items, mut notes) = (Vec::new(), Vec::new());
    for r in requirements {
        let (item, note) = match r {
            PolicyRequirement::InsecureAcceptAnything => (Item::AcceptAnything, String::new()),
            PolicyRequirement::Reject => (Item::Reject, String::new()),
            PolicyRequirement::SignedBaseLayer { .. } => (Item::Unimplemented, String::new()),
            PolicyRequirement::SignedBy {
                key_type,
                key_path,
                key_paths,
                key_data,
                signed_identity,
            } => signed_by(
                *key_type,
                key_path.as_deref(),
                key_paths.as_deref(),
                key_data.as_deref(),
                signed_identity.as_ref(),
                image,
                now,
            )
            .unwrap_or_else(unusable),
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
            } => (|| {
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
                let root = TrustRoot {
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
                };
                root.check().map_err(|e| e.0)?;
                Ok(sigstore_signed(&root, signed_identity.as_ref(), image, now))
            })()
            .unwrap_or_else(unusable),
        };
        items.push(item);
        notes.push(note);
    }
    match decide(mode, &image.reference.to_core(), &items) {
        Outcome::Accept { mut used, signed } => {
            used.sort_unstable();
            used.dedup();
            Ok((used, signed))
        }
        Outcome::Refuse { at, why } => Err(match why {
            Why::Rejected => format!("{} is rejected by policy", image.reference.string()),
            Why::Unimplemented => "signedBaseLayer requirements are not implemented".into(),
            Why::Empty => "no requirement applies".into(),
            Why::Unusable | Why::NoSignature => std::mem::take(&mut notes[at]),
            Why::NotSigned => refusal(why).into(),
        }),
    }
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

/// The fact a verified payload is: it must name the manifest and the
/// reference of the image, and when it does not, the reason is kept in
/// `rejections`.
fn payload_fact(
    payload: &sigstore::Payload,
    identity: Option<&SignedIdentity>,
    image: &Image,
    rejections: &mut Vec<String>,
) -> Fact {
    let digest_matches = image.manifest.has_digest(&payload.manifest_digest);
    if !digest_matches {
        rejections.push(format!(
            "signature for digest {} does not match",
            payload.manifest_digest
        ));
    } else if !identity
        .cloned()
        .unwrap_or_default()
        .matches(image.reference, &payload.docker_reference)
    {
        rejections.push(format!(
            "signature for identity {:?} is not accepted",
            payload.docker_reference
        ));
    }
    match DockerRef::parse_normalized(&payload.docker_reference) {
        Ok(signed) => Fact::Verified {
            digest_matches,
            signed: signed.to_core(),
            time: payload.timestamp,
        },
        Err(_) => Fact::Unverified,
    }
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
) -> Result<(Item, String), String> {
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
    let (mut rejections, mut facts) = (Vec::new(), Vec::new());
    for sig in image.signatures {
        let Signature::Simple(blob) = sig else {
            facts.push(Fact::Unverified);
            continue;
        };
        let result = openpgp::verify_message(&keys, blob, u64::try_from(now).unwrap_or(0))
            .map_err(|e| e.0)
            .and_then(|(content, _)| {
                sigstore::parse_payload(&content, sigstore::SIMPLE_SIGNING_TYPE).map_err(|e| e.0)
            });
        facts.push(match result {
            Ok(payload) => payload_fact(&payload, identity, image, &mut rejections),
            Err(e) => {
                rejections.push(e);
                Fact::Unverified
            }
        });
    }
    let rule = identity.cloned().unwrap_or_default().rule(image.reference);
    Ok((
        Item::Signed(rule, facts),
        summary(rejections, NO_SIGNATURE.into()),
    ))
}

fn sigstore_signed(
    root: &TrustRoot,
    identity: Option<&SignedIdentity>,
    image: &Image,
    now: i64,
) -> (Item, String) {
    let (mut rejections, mut facts) = (Vec::new(), Vec::new());
    let (mut others, mut attachments) = (0, 0);
    for sig in image.signatures {
        let Signature::Sigstore(s) = sig else {
            others += 1;
            facts.push(Fact::Unverified);
            continue;
        };
        if s.mime_type != sigstore::SIGSTORE_MEDIA_TYPE {
            attachments += 1;
            facts.push(Fact::Unverified);
            continue;
        }
        facts.push(match root.verify(s, now) {
            Ok(payload) => payload_fact(&payload, identity, image, &mut rejections),
            Err(e) => {
                rejections.push(e.0);
                Fact::Unverified
            }
        });
    }
    let none = if others + attachments == 0 {
        NO_SIGNATURE.to_string()
    } else {
        format!("{NO_SIGNATURE} ({others} non-sigstore signatures, {attachments} sigstore non-signature attachments)")
    };
    let rule = identity.cloned().unwrap_or_default().rule(image.reference);
    (Item::Signed(rule, facts), summary(rejections, none))
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
        assert!(needs_signatures(Mode::Whole, &r));
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
            Mode::Whole,
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

    /// A sigstoreSigned requirement of `key`.
    fn trusting(key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Vec<PolicyRequirement> {
        reqs(&format!(
            r#"[{{"type": "sigstoreSigned", "keyData": "{}"}}]"#,
            b64(&key.public_key_to_pem().unwrap())
        ))
    }

    /// A signedBy requirement of the key of the fixtures `keys`.
    fn trusting_gpg(keys: &[u8]) -> Vec<PolicyRequirement> {
        reqs(&format!(
            r#"[{{"type": "signedBy", "keyType": "GPGKeys", "keyData": "{}"}}]"#,
            b64(keys)
        ))
    }

    /// The payload of a sigstore signature for `name`, signed at `time`.
    fn payload_at(digest: &str, name: &str, time: i64) -> Vec<u8> {
        String::from_utf8(payload(sigstore::SIGSTORE_TYPE, name))
            .unwrap()
            .replace(crate::sigstore::tests::DIGEST, digest)
            .replace(r#""creator":"test""#, &format!(r#""timestamp":{time}"#))
            .into_bytes()
    }

    /// Every requirement of the list must accept the image, in whatever
    /// order and whatever the kind: a signature of a trusted key for the
    /// manifest and the name satisfies a requirement, and the signatures
    /// that satisfied them are the ones reported.  A `reject`, a
    /// `signedBaseLayer` and a requirement that cannot be used refuse the
    /// image whatever the signatures.
    #[test]
    fn the_requirements_of_a_list_all_have_to_accept() {
        let (good, other) = (ec_key(), ec_key());
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(openssl::sha::sha256(manifest)));
        let name = "localhost:5000/signed/image:v1";
        let reference = DockerRef::parse_normalized(name).unwrap();
        // the signatures of the image: 0 is by a key of OpenPGP, 1 by `good`
        let sigs = [
            Signature::Simple(fixture!("msg-rsa-manifest.sig").to_vec()),
            Signature::Sigstore(signature(&good, &payload_at(&digest, name, 1), None)),
        ];
        let image = Image {
            reference: &reference,
            manifest: Manifest::Bytes(manifest),
            signatures: &sigs,
        };
        let gpg = || trusting_gpg(fixture!("key-rsa.gpg"));
        let gpg_other = || trusting_gpg(fixture!("key-ed.gpg"));
        let anything = || reqs(r#"[{"type": "insecureAcceptAnything"}]"#);
        let reject = || reqs(r#"[{"type": "reject"}]"#);
        let base_layer = || reqs(r#"[{"type": "signedBaseLayer"}]"#);
        let unusable =
            || reqs(r#"[{"type": "sigstoreSigned", "keyPath": "/nonexistent/key.pem"}]"#);
        let cases = vec![
            ("only insecureAcceptAnything", anything(), Some(vec![])),
            ("sigstoreSigned", trusting(&good), Some(vec![1])),
            ("signedBy", gpg(), Some(vec![0])),
            (
                "both kinds",
                [gpg(), trusting(&good)].concat(),
                Some(vec![0, 1]),
            ),
            (
                "insecureAcceptAnything beside a signature",
                [anything(), trusting(&good)].concat(),
                Some(vec![1]),
            ),
            (
                "the same requirement twice",
                [trusting(&good), trusting(&good)].concat(),
                Some(vec![1]),
            ),
            ("a key that did not sign", trusting(&other), None),
            ("signedBy of another key", gpg_other(), None),
            (
                "one that holds, one that does not",
                [trusting(&good), trusting(&other)].concat(),
                None,
            ),
            (
                "one that does not, one that holds",
                [trusting(&other), trusting(&good)].concat(),
                None,
            ),
            (
                "signedBy that holds, sigstoreSigned that does not",
                [gpg(), trusting(&other)].concat(),
                None,
            ),
            ("reject", reject(), None),
            (
                "reject after a signature that holds",
                [trusting(&good), reject()].concat(),
                None,
            ),
            (
                "reject before a signature that holds",
                [reject(), trusting(&good)].concat(),
                None,
            ),
            ("signedBaseLayer", base_layer(), None),
            (
                "signedBaseLayer beside a signature that holds",
                [trusting(&good), base_layer()].concat(),
                None,
            ),
            ("a key that cannot be loaded", unusable(), None),
            (
                "a key that cannot be loaded, after one that holds",
                [trusting(&good), unusable()].concat(),
                None,
            ),
            ("no requirement", Vec::new(), None),
        ];
        for (what, requirements, expected) in cases {
            let got = accepted(Mode::Whole, &requirements, &image, NOW).ok();
            assert_eq!(got, expected, "{what}");
        }
    }

    /// The time an image was signed at is, for each signature requirement,
    /// its newest signature, and of those the oldest; 0 when no requirement
    /// needs a signature.
    #[test]
    fn the_time_of_signing_is_the_oldest_of_the_newest_of_each_requirement() {
        let (first, second) = (ec_key(), ec_key());
        let name = "quay.io/a/b:v1";
        let reference = DockerRef::parse_normalized(name).unwrap();
        let digest = crate::sigstore::tests::DIGEST;
        let sigs = [
            Signature::Sigstore(signature(&first, &payload_at(digest, name, 100), None)),
            Signature::Sigstore(signature(&first, &payload_at(digest, name, 300), None)),
            Signature::Sigstore(signature(&second, &payload_at(digest, name, 200), None)),
        ];
        let image = Image {
            reference: &reference,
            manifest: Manifest::Digest(digest),
            signatures: &sigs,
        };
        let both = [trusting(&first), trusting(&second)].concat();
        assert_eq!(
            accepted_at(Mode::Whole, &both, &image, NOW).unwrap(),
            (vec![1, 2], 200)
        );
        assert_eq!(
            accepted_at(Mode::Whole, &trusting(&first), &image, NOW).unwrap(),
            (vec![1], 300)
        );
        let anything = reqs(r#"[{"type": "insecureAcceptAnything"}]"#);
        assert_eq!(
            accepted_at(Mode::Whole, &anything, &image, NOW).unwrap(),
            (vec![], 0)
        );
    }

    /// What each kind of requirement says before any signature is fetched,
    /// as a pull and as the create of a stored image judge it.
    #[test]
    fn the_kinds_of_requirement_say_what_they_need_before_the_signatures() {
        let said = |mode, r: &[PolicyRequirement]| match precheck(mode, r) {
            Pre::Accept => "accepts".to_string(),
            Pre::NeedsSignatures => "needs signatures".to_string(),
            Pre::Refuse { at, why } => format!("{at}: {}", refusal(why)),
        };
        for (json, pull, create) in [
            (
                r#"{"type": "insecureAcceptAnything"}"#,
                "accepts",
                "accepts",
            ),
            (r#"{"type": "reject"}"#, "0: rejects it", "accepts"),
            (
                r#"{"type": "signedBaseLayer"}"#,
                "0: has a signedBaseLayer requirement, which is not implemented",
                "accepts",
            ),
            (
                r#"{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k"}"#,
                "needs signatures",
                "needs signatures",
            ),
            (
                r#"{"type": "sigstoreSigned", "keyPath": "/k"}"#,
                "needs signatures",
                "needs signatures",
            ),
        ] {
            let r = reqs(&format!("[{json}]"));
            assert_eq!(said(Mode::Whole, &r), pull, "{json}");
            assert_eq!(said(Mode::SignaturesOnly, &r), create, "{json}");
        }
        // the first of a mixed list that refuses says why
        let mixed = reqs(
            r#"[{"type": "sigstoreSigned", "keyPath": "/a"}, {"type": "reject"},
                {"type": "insecureAcceptAnything"}, {"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/b"}]"#,
        );
        assert!(needs_signatures(Mode::Whole, &mixed));
        assert_eq!(said(Mode::Whole, &mixed), "1: rejects it");
        assert_eq!(said(Mode::SignaturesOnly, &mixed), "needs signatures");
    }
}
