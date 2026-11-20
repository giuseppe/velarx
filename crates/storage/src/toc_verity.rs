// SPDX-License-Identifier: Apache-2.0
//! The fs-verity digest of a regular file in a zstd:chunked TOC: the
//! `fsverity` field of its entry, `<hash>-<log2 block size>:<hex>`.  The
//! store names its objects by the fs-verity digest with SHA-256 or SHA-512
//! over blocks of 4096 bytes and no salt (`fsverity-<alg>-12:<hex>`,
//! [`crate::Object`]), so those are the only kinds written and understood
//! here (`sha256-12`, `sha512-12`); a value of another kind is not one (the
//! file is treated as if the TOC had none).

use super::VerityHasher;
use velarx_types::digest::{parse_toc_fsverity, Algorithm, Digest};

/// The fs-verity digest the object digest `fsverity-<alg>-12:<hex>` is, as
/// the `fsverity` of a TOC entry keeps it.
pub fn to_toc(object: &str) -> Option<Digest> {
    Digest::parse_fsverity(object).ok()
}

/// The TOC value of a fs-verity digest of the store (`<alg>-12:<hex>`).
pub fn toc_value(digest: &Digest) -> String {
    format!("{}-12:{}", digest.alg(), digest.hex())
}

/// The `fsverity` of an entry as the TOC writes it: the text of
/// [`toc_value`], read once into the digest; a value that is no digest of
/// the store is none (the file is treated as if the TOC had none).
pub(crate) mod field {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(digest: &Option<Digest>, s: S) -> Result<S::Ok, S::Error> {
        match digest {
            Some(d) => s.serialize_str(&toc_value(d)),
            None => s.serialize_none(),
        }
    }

    struct Value;

    impl<'de> serde::de::Visitor<'de> for Value {
        type Value = Option<Digest>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the fs-verity digest of a file, `<alg>-12:<hex>`")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E> {
            Ok(parse_toc_fsverity(text))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_str(self)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Digest>, D::Error> {
        d.deserialize_option(Value)
    }
}

/// The object digest (`fsverity-<alg>-12:<hex>`) a TOC value names, if it is
/// of a kind the store uses.
pub fn from_toc(value: &str) -> Option<String> {
    parse_toc_fsverity(value).map(|d| d.to_string())
}

/// The TOC value of the content fed to it in `alg`, as a layer is written.
pub struct TocVerityHasher(VerityHasher);

impl TocVerityHasher {
    pub fn new(alg: Algorithm) -> Self {
        Self(VerityHasher::new(alg))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The same as `update` with `len` bytes of zeros.
    pub fn update_zeros(&mut self, len: u64) {
        self.0.update_zeros(len);
    }

    pub fn finish(self) -> Digest {
        let object = self.0.finish();
        Digest::parse_fsverity(&object).expect("the object digest of a hasher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_name_the_kind_of_digest() {
        for alg in Algorithm::ALL {
            let object = crate::fsverity_digest_of(alg, b"hello\n");
            let digest = to_toc(&object).unwrap();
            let toc = toc_value(&digest);
            assert!(toc.starts_with(&format!("{alg}-12:")), "{toc}");
            assert_eq!(from_toc(&toc).as_deref(), Some(object.as_str()));
            let mut h = TocVerityHasher::new(alg);
            h.update(b"hel");
            h.update(b"lo\n");
            assert_eq!(h.finish(), digest);
            // other kinds and malformed values are no digest
            let hex = object.split_once(':').unwrap().1;
            for bad in [
                format!("sha384-12:{hex}"),
                format!("{alg}-16:{hex}"),
                format!("{alg}:{hex}"),
                format!("{alg}-12:{}", hex.to_uppercase()),
                format!("{alg}-12:abc"),
            ] {
                assert_eq!(from_toc(&bad), None, "{bad}");
            }
        }
        // the digits tell the algorithm: a SHA-256 value with the digits of
        // a SHA-512 one is none
        let sha512 = crate::fsverity_digest_of(Algorithm::Sha512, b"hello\n");
        let hex = sha512.split_once(':').unwrap().1;
        assert_eq!(from_toc(&format!("sha256-12:{hex}")), None);
        assert_eq!(to_toc("sha256:xyz"), None);
        // an OCI digest is no object
        let oci = Digest::of(Algorithm::Sha256, b"x").to_string();
        assert_eq!(to_toc(&oci), None);
    }

    #[test]
    fn an_entry_keeps_the_fs_verity_digest_the_table_wrote() {
        let hex = "ab".repeat(32);
        let entry = |value: &str| -> crate::TocEntry {
            serde_json::from_str(&format!(
                r#"{{"name":"f","type":"reg","size":1,"fsverity":"{value}"}}"#
            ))
            .unwrap()
        };
        let e = entry(&format!("sha256-12:{hex}"));
        assert_eq!(e.verity().unwrap(), format!("fsverity-sha256-12:{hex}"));
        let written = serde_json::to_value(&e).unwrap();
        assert_eq!(written["fsverity"], format!("sha256-12:{hex}"));
        // a value that is no digest of the store is the table of a layer
        // that gives the file none
        for bad in [
            "sha384-12:00".to_string(),
            format!("sha256-12:{}", hex.to_uppercase()),
            format!("sha256-16:{hex}"),
            hex.clone(),
        ] {
            assert!(entry(&bad).fsverity.is_none(), "{bad}");
        }
    }
}
