// SPDX-License-Identifier: Apache-2.0
//! What a tag names, from signatures alone: a record is a manifest digest
//! with the signatures made for it, and a tag is taken from the newest
//! record that the policy accepts for exactly that name.

use super::evaluate::{self, Image, Manifest, Mode};
use super::policy::PolicyRequirement;
use super::reference::{DockerRef, SignedIdentity};
use super::sigstore::Signature;
use velarx_policy_core::{pick, Picked, Signed};

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
    if !evaluate::needs_signatures(Mode::SignaturesOnly, requirements) {
        return Ok(None);
    }
    let requirements = exact(requirements);
    // the records the policy accepts, with when each was signed
    let mut accepted = Vec::new();
    let mut signed = Vec::new();
    for record in records {
        let image = Image {
            reference,
            manifest: Manifest::Digest(&record.digest),
            signatures: &record.signatures,
        };
        if let Ok((_, time)) =
            evaluate::accepted_at(Mode::SignaturesOnly, &requirements, &image, now)
        {
            signed.push(Signed {
                time,
                digest: record.digest.as_bytes().to_vec(),
            });
            accepted.push(record.digest);
        }
    }
    match pick(&signed) {
        Picked::Nothing => Ok(None),
        Picked::One(i) => Ok(Some(Named {
            digest: accepted.swap_remove(i),
            signed: signed[i].time,
        })),
        Picked::Tie(i, j) => Err(format!(
            "two records signed at the same time name {} and {}",
            accepted[i], accepted[j]
        )),
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
        assert!(newest(&[], &name, records(), 0).unwrap().is_none());
        let mixed = [anything, requirements(&key, "")].concat();
        let got = newest(&mixed, &name, records(), 0).unwrap().unwrap();
        assert_eq!(got.digest, DIGEST);
    }

    /// A record names the tag only when every signature requirement
    /// accepts it; a `reject` beside them is not a signature requirement.
    #[test]
    fn a_record_must_satisfy_every_signature_requirement() {
        let (first, second) = (ec_key(), ec_key());
        let name = DockerRef::parse_normalized(NAME).unwrap();
        let both = [requirements(&first, ""), requirements(&second, "")].concat();
        let by_first = || record(&first, (NAME, DIGEST), 10);
        assert!(newest(&both, &name, vec![by_first()], 0).unwrap().is_none());
        let mut by_both = by_first();
        by_both
            .signatures
            .extend(record(&second, (NAME, DIGEST), 20).signatures);
        let got = newest(&both, &name, vec![by_both], 0).unwrap().unwrap();
        // (the oldest of the newest signature of each requirement)
        assert_eq!((got.digest.as_str(), got.signed), (DIGEST, 10));
        let rejecting = [requirements(&first, ""), vec![PolicyRequirement::Reject]].concat();
        let got = newest(&rejecting, &name, vec![by_first()], 0).unwrap();
        assert_eq!(got.map(|n| n.digest).as_deref(), Some(DIGEST));
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

    /// Which digest and time a list of (digest, time) names, or the error,
    /// whatever the order of arrival.
    fn named_in_every_order(
        key: &PKey<Private>,
        list: &[(&str, i64)],
    ) -> Vec<Result<(String, i64), String>> {
        let mut orders: Vec<Vec<usize>> = vec![Vec::new()];
        for _ in list {
            let mut longer = Vec::new();
            for order in &orders {
                for i in (0..list.len()).filter(|i| !order.contains(i)) {
                    longer.push([order.clone(), vec![i]].concat());
                }
            }
            orders = longer;
        }
        orders
            .iter()
            .map(|o| {
                let records = o.iter().map(|&i| record(key, (NAME, list[i].0), list[i].1));
                newest_of(key, records.collect()).map(|n| n.map(|n| (n.digest, n.signed)).unwrap())
            })
            .collect()
    }

    /// Pins the pick: a record strictly later than the others names the
    /// tag wherever it arrives, and below it a tie does not matter.
    #[test]
    fn a_strictly_later_record_wins_in_every_order() {
        let key = ec_key();
        let list = [(DIGEST, 10), (OTHER, 10), (OTHER, 20), (DIGEST, 5)];
        for got in named_in_every_order(&key, &list) {
            assert_eq!(got, Ok((OTHER.to_string(), 20)));
        }
    }

    /// Pins the pick: a tie of the latest time is an error in every order,
    /// and a record of the same digest among them does not undo it
    /// (`A, B, A` at one time).
    #[test]
    fn a_tie_at_the_latest_time_is_an_error_in_every_order() {
        let key = ec_key();
        for list in [
            vec![(DIGEST, 10), (OTHER, 10)],
            vec![(DIGEST, 10), (OTHER, 10), (DIGEST, 10)],
            vec![(DIGEST, 10), (OTHER, 10), (DIGEST, 5)],
        ] {
            for got in named_in_every_order(&key, &list) {
                let e = got.unwrap_err();
                assert!(e.contains(DIGEST) && e.contains(OTHER), "{e}");
            }
        }
    }

    /// Pins the pick: equal records of one time name that digest in every
    /// order, a record refused by the policy takes no part (not even as a
    /// later one), and no record names nothing.
    #[test]
    fn equal_records_name_their_digest_and_refused_ones_take_no_part() {
        let key = ec_key();
        let list = [(OTHER, 10), (OTHER, 10), (OTHER, 10)];
        for got in named_in_every_order(&key, &list) {
            assert_eq!(got, Ok((OTHER.to_string(), 10)));
        }
        let other = ec_key();
        for records in [
            vec![
                record(&other, (NAME, DIGEST), 99),
                record(&key, (NAME, OTHER), 10),
                record(&other, (NAME, OTHER), 99),
            ],
            vec![
                record(&key, (NAME, OTHER), 10),
                record(&other, (NAME, DIGEST), 10),
            ],
        ] {
            let got = newest_of(&key, records).unwrap().unwrap();
            assert_eq!((got.digest.as_str(), got.signed), (OTHER, 10));
        }
        assert!(newest_of(&key, vec![record(&other, (NAME, DIGEST), 10)])
            .unwrap()
            .is_none());
    }
}
