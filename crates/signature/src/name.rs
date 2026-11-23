// SPDX-License-Identifier: Apache-2.0
//! What a tag names, from signatures alone: a record is a manifest digest
//! with the signatures made for it, and a tag is taken from the newest
//! record that the policy accepts for exactly that name.

use super::evaluate::{self, Image, Manifest};
use super::policy::PolicyRequirement;
use super::reference::{DockerRef, SignedIdentity};
use super::sigstore::Signature;

/// A manifest digest and the signatures that name it (untrusted: a
/// peer's claim until the policy has judged them).
pub struct Record {
    pub digest: String,
    pub signatures: Vec<Signature>,
}

/// The record a tag resolves to.
pub struct Named {
    pub digest: String,
    /// When it was signed
    pub signed: i64,
}

/// The requirements as they apply to a tag: a signature counts only when
/// it names exactly `reference` (a `matchRepository` rule would make the
/// signature of one tag the record of another).
fn exact(requirements: &[PolicyRequirement]) -> Vec<PolicyRequirement> {
    let mut requirements = requirements.to_vec();
    for r in &mut requirements {
        if let PolicyRequirement::SignedBy {
            signed_identity, ..
        }
        | PolicyRequirement::SigstoreSigned {
            signed_identity, ..
        } = r
        {
            *signed_identity = Some(SignedIdentity::MatchExact);
        }
    }
    requirements
}

/// The record of `records` that the signature requirements of
/// `requirements` (those of the scope of `reference`, a name with a tag)
/// accept with the latest time of signing; None when none is accepted, or
/// when no requirement asks for a signature (then no signature says what
/// a tag names).  Two accepted records of the same time that name
/// different digests are an error.
pub fn newest(
    requirements: &[PolicyRequirement],
    reference: &DockerRef,
    records: Vec<Record>,
    now: i64,
) -> Result<Option<Named>, String> {
    let requirements = exact(&evaluate::signature_requirements(requirements));
    if requirements.is_empty() {
        return Ok(None);
    }
    let mut best: Option<Named> = None;
    // (another digest signed at the time of `best`)
    let mut tie = None;
    for record in records {
        let image = Image {
            reference,
            manifest: Manifest::Digest(&record.digest),
            signatures: &record.signatures,
        };
        let Ok((_, signed)) = evaluate::accepted_at(&requirements, &image, now) else {
            continue;
        };
        match &best {
            Some(have) if signed < have.signed => continue,
            Some(have) if signed == have.signed => {
                if record.digest != have.digest {
                    tie = Some(record.digest);
                }
                continue;
            }
            _ => {}
        }
        tie = None;
        best = Some(Named {
            signed,
            digest: record.digest,
        });
    }
    match (best, tie) {
        (Some(have), Some(other)) => Err(format!(
            "two records signed at the same time name {} and {other}",
            have.digest
        )),
        (best, _) => Ok(best),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::tests::{ec_key, signature, DIGEST};
    use base64::Engine;
    use openssl::pkey::{PKey, Private};

    const OTHER: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const NAME: &str = "quay.io/a/b:v1";

    fn requirements(key: &PKey<Private>, identity: &str) -> Vec<PolicyRequirement> {
        let pem = key.public_key_to_pem().unwrap();
        let data = base64::engine::general_purpose::STANDARD.encode(pem);
        serde_json::from_str(&format!(
            r#"[{{"type": "sigstoreSigned", "keyData": "{data}"{identity}}}]"#
        ))
        .unwrap()
    }

    /// A record of `digest` signed by `key` for `name` at `time`.
    fn record(key: &PKey<Private>, (name, digest): (&str, &str), time: i64) -> Record {
        let payload = String::from_utf8(crate::sigstore::tests::payload(
            crate::sigstore::SIGSTORE_TYPE,
            name,
        ))
        .unwrap()
        .replace(DIGEST, digest)
        .replace(r#""creator":"test""#, &format!(r#""timestamp":{time}"#));
        Record {
            digest: digest.into(),
            signatures: vec![Signature::Sigstore(signature(
                key,
                payload.as_bytes(),
                None,
            ))],
        }
    }

    fn newest_of(key: &PKey<Private>, records: Vec<Record>) -> Result<Option<Named>, String> {
        let name = DockerRef::parse_normalized(NAME).unwrap();
        newest(&requirements(key, ""), &name, records, 0)
    }

    #[test]
    fn the_newest_valid_record_wins() {
        let key = ec_key();
        let got = newest_of(
            &key,
            vec![
                record(&key, (NAME, DIGEST), 20),
                record(&key, (NAME, OTHER), 30),
                record(&key, (NAME, DIGEST), 10),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!((got.digest.as_str(), got.signed), (OTHER, 30));
    }

    /// A tie is an error only when no record is newer, in any order; and a
    /// record signed again is as new as its newest signature.
    #[test]
    fn a_newer_record_ends_a_tie_and_signing_again_makes_a_record_new() {
        let key = ec_key();
        let got = newest_of(
            &key,
            vec![
                record(&key, (NAME, DIGEST), 10),
                record(&key, (NAME, OTHER), 10),
                record(&key, (NAME, OTHER), 20),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!((got.digest.as_str(), got.signed), (OTHER, 20));
        let mut again = record(&key, (NAME, DIGEST), 10);
        again
            .signatures
            .extend(record(&key, (NAME, DIGEST), 30).signatures);
        let got = newest_of(&key, vec![again, record(&key, (NAME, OTHER), 20)])
            .unwrap()
            .unwrap();
        assert_eq!((got.digest.as_str(), got.signed), (DIGEST, 30));
    }

    #[test]
    fn a_record_of_another_key_name_or_tag_is_dropped() {
        let (key, other) = (ec_key(), ec_key());
        let got = newest_of(
            &key,
            vec![
                record(&key, (NAME, DIGEST), 10),
                // newer, and each wrong in one way
                record(&other, (NAME, OTHER), 50),
                record(&key, ("quay.io/a/b:v2", OTHER), 40),
                record(&key, ("quay.io/a/c:v1", OTHER), 30),
                record(&key, ("quay.io/a/b", OTHER), 20),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.digest, DIGEST);
        let none = newest_of(&key, vec![record(&other, (NAME, DIGEST), 10)]).unwrap();
        assert!(none.is_none());
        assert!(newest_of(&key, Vec::new()).unwrap().is_none());
    }

    /// A rule that accepts a signature of any tag of the repository does
    /// not make it the record of this tag.
    #[test]
    fn the_signed_name_is_exact_whatever_the_policy_says() {
        let key = ec_key();
        let loose = requirements(&key, r#", "signedIdentity": {"type": "matchRepository"}"#);
        let name = DockerRef::parse_normalized(NAME).unwrap();
        let v2 = record(&key, ("quay.io/a/b:v2", DIGEST), 10);
        assert!(newest(&loose, &name, vec![v2], 0).unwrap().is_none());
    }

    /// Only a signature requirement names a tag: a policy that accepts
    /// anything accepts no record, and its other rules are left out.
    #[test]
    fn a_policy_with_no_signature_requirement_names_nothing() {
        let key = ec_key();
        let name = DockerRef::parse_normalized(NAME).unwrap();
        let anything: Vec<PolicyRequirement> =
            serde_json::from_str(r#"[{"type": "insecureAcceptAnything"}]"#).unwrap();
        let records = || vec![record(&key, (NAME, DIGEST), 10)];
        assert!(newest(&anything, &name, records(), 0).unwrap().is_none());
        let mixed = [anything, requirements(&key, "")].concat();
        let got = newest(&mixed, &name, records(), 0).unwrap().unwrap();
        assert_eq!(got.digest, DIGEST);
    }

    #[test]
    fn two_digests_signed_at_the_same_time_are_an_error() {
        let key = ec_key();
        let e = newest_of(
            &key,
            vec![
                record(&key, (NAME, DIGEST), 10),
                record(&key, (NAME, OTHER), 10),
            ],
        )
        .err()
        .unwrap();
        assert!(e.contains(DIGEST) && e.contains(OTHER), "{e}");
        // the same digest twice is one record
        let same = newest_of(
            &key,
            vec![
                record(&key, (NAME, DIGEST), 10),
                record(&key, (NAME, DIGEST), 10),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(same.digest, DIGEST);
    }
}
