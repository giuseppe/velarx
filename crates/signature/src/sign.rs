// SPDX-License-Identifier: Apache-2.0
//! Signing an image as `skopeo copy --sign-by-sigstore-private-key` and
//! `podman push` do: a sigstore (cosign) signature of the manifest digest,
//! made with the private key of `cosign generate-key-pair` or
//! `skopeo generate-sigstore-key`.
//!
//! Such a key is a PEM block holding a JSON document: the scrypt
//! parameters, and the PKCS#8 key sealed with the NaCl secretbox
//! (XSalsa20 and Poly1305) under the key scrypt derives from the
//! passphrase: scrypt is OpenSSL's, XSalsa20 and Poly1305 (which OpenSSL
//! lacks) are RustCrypto's.

use crate::sigstore::{Error, Sigstore, SIGNATURE_ANNOTATION, SIGSTORE_MEDIA_TYPE, SIGSTORE_TYPE};
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer as SslSigner;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// The PEM types of an encrypted private key: cosign's (both spellings of
/// it) and sigstore's.
const KEY_LABELS: &[&str] = &[
    "ENCRYPTED COSIGN PRIVATE KEY",
    "COSIGN ENCRYPTED PRIVATE KEY",
    "ENCRYPTED SIGSTORE PRIVATE KEY",
];

/// Largest scrypt memory a key may ask for.
const MAX_SCRYPT_MEMORY: u64 = 1 << 30;

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// The private key and passphrase of a signature as they were read from
/// the user's files, to load in the engine.  It never prints them.
#[derive(Clone)]
pub struct KeyFiles {
    pub key: Vec<u8>,
    pub passphrase: Vec<u8>,
}

impl std::fmt::Debug for KeyFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyFiles(<redacted>)")
    }
}

impl Drop for KeyFiles {
    fn drop(&mut self) {
        self.key.zeroize();
        self.passphrase.zeroize();
    }
}

/// A loaded private key.
pub struct Signer {
    key: PKey<Private>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer(<redacted>)")
    }
}

impl Signer {
    /// The key of `files`, decrypted.
    pub fn load(files: &KeyFiles) -> Result<Self, Error> {
        let der = decrypt_key(&files.key, &files.passphrase)?;
        let key = PKey::private_key_from_der(&der)
            .map_err(|_| Error("the private key is not a PKCS#8 key".into()))?;
        match key.id() {
            Id::EC | Id::RSA | Id::ED25519 => Ok(Self { key }),
            _ => err("the private key is neither ECDSA, RSA nor Ed25519"),
        }
    }

    /// The signature of the manifest `digest` for the image named
    /// `reference` (a normalized name, with its tag when it has one), at
    /// `now` seconds since the epoch.
    pub fn sign_manifest(
        &self,
        digest: &str,
        reference: &str,
        creator: &str,
        now: i64,
    ) -> Result<Sigstore, Error> {
        let payload = payload(SIGSTORE_TYPE, digest, reference, creator, now);
        let sig = self.sign(&payload)?;
        let mut annotations = BTreeMap::new();
        annotations.insert(
            SIGNATURE_ANNOTATION.to_string(),
            base64::engine::general_purpose::STANDARD.encode(sig),
        );
        Ok(Sigstore {
            mime_type: SIGSTORE_MEDIA_TYPE.into(),
            payload,
            annotations,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let ssl = |e: openssl::error::ErrorStack| Error(format!("signing: {e}"));
        if self.key.id() == Id::ED25519 {
            let mut s = SslSigner::new_without_digest(&self.key).map_err(ssl)?;
            return s.sign_oneshot_to_vec(data).map_err(ssl);
        }
        let mut s = SslSigner::new(MessageDigest::sha256(), &self.key).map_err(ssl)?;
        s.update(data).map_err(ssl)?;
        s.sign_to_vec().map_err(ssl)
    }
}

/// The payload of a signature of `kind` (`SIGSTORE_TYPE` or
/// `SIMPLE_SIGNING_TYPE`), with the fields containers/image writes.
pub fn payload(kind: &str, digest: &str, reference: &str, creator: &str, now: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "critical": {
            "identity": {"docker-reference": reference},
            "image": {"docker-manifest-digest": digest},
            "type": kind,
        },
        "optional": {"creator": creator, "timestamp": now},
    }))
    .unwrap_or_default()
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Envelope {
    kdf: Kdf,
    cipher: Cipher,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Kdf {
    name: String,
    params: ScryptParams,
    #[serde(with = "b64")]
    salt: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ScryptParams {
    #[serde(rename = "N")]
    n: u64,
    r: u64,
    p: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Cipher {
    name: String,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// The DER of the PKCS#8 key sealed in `pem`.
fn decrypt_key(pem: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let text = std::str::from_utf8(pem).map_err(|_| Error("the key is not a PEM file".into()))?;
    let text = text.trim();
    let first = text.lines().next().unwrap_or_default();
    let label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or_else(|| Error("the key is not a PEM file".into()))?;
    if !KEY_LABELS.contains(&label) {
        return err(format!(
            "unsupported private key type {label:?}: velarx signs with a key of cosign or \
             `skopeo generate-sigstore-key` (ENCRYPTED COSIGN PRIVATE KEY)"
        ));
    }
    let end = format!("-----END {label}-----");
    let Some(body_end) = text.find(&end) else {
        return err("the key PEM has no end");
    };
    if !text[body_end + end.len()..].trim().is_empty() {
        return err("the key PEM has data after its end");
    }
    let body: String = text[first.len()..body_end].lines().map(str::trim).collect();
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| Error("invalid base64 in the key".into()))?;
    let env: Envelope = serde_json::from_slice(&envelope)
        .map_err(|e| Error(format!("invalid private key document: {e}")))?;
    if env.kdf.name != "scrypt" {
        return err(format!("unsupported key derivation {:?}", env.kdf.name));
    }
    if env.cipher.name != "nacl/secretbox" {
        return err(format!("unsupported key cipher {:?}", env.cipher.name));
    }
    let nonce: [u8; 24] = env
        .cipher
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error("the key nonce is not 24 bytes".into()))?;
    let ScryptParams { n, r, p } = env.kdf.params;
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 || r > 64 || p > 64 {
        return err("invalid scrypt parameters in the key");
    }
    if n.saturating_mul(r).saturating_mul(128) > MAX_SCRYPT_MEMORY {
        return err("the scrypt parameters of the key ask for too much memory");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    openssl::pkcs5::scrypt(
        passphrase,
        &env.kdf.salt,
        n,
        r,
        p,
        MAX_SCRYPT_MEMORY * 2,
        key.as_mut_slice(),
    )
    .map_err(|e| Error(format!("scrypt: {e}")))?;
    secretbox_open(&key, &nonce, &env.ciphertext)
        .ok_or_else(|| Error("cannot decrypt the private key: wrong passphrase?".into()))
}

/// Open a NaCl secretbox (the tag, then the ciphertext): XSalsa20 and
/// Poly1305 of RustCrypto, the tag compared in constant time before
/// anything is decrypted.
fn secretbox_open(key: &[u8; 32], nonce: &[u8; 24], boxed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use poly1305::universal_hash::KeyInit;
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    if boxed.len() < 16 {
        return None;
    }
    let (tag, ciphertext) = boxed.split_at(16);
    let mut cipher = salsa20::XSalsa20::new(key.into(), nonce.into());
    // the first 32 bytes of the stream are the one-time key of Poly1305
    let mut mac_key = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(mac_key.as_mut_slice());
    let expected = poly1305::Poly1305::new(poly1305::Key::from_slice(mac_key.as_slice()))
        .compute_unpadded(ciphertext);
    if !openssl::memcmp::eq(expected.as_slice(), tag) {
        return None;
    }
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    cipher.apply_keystream(&mut plain);
    Some(plain)
}

/// Seal `plain` as NaCl's secretbox does: the Poly1305 tag, then the
/// XSalsa20 ciphertext.
fn secretbox_seal(key: &[u8; 32], nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    use poly1305::universal_hash::KeyInit;
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    let mut cipher = salsa20::XSalsa20::new(key.into(), nonce.into());
    let mut mac_key = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(mac_key.as_mut_slice());
    let mut data = plain.to_vec();
    cipher.apply_keystream(&mut data);
    let mut out = poly1305::Poly1305::new(poly1305::Key::from_slice(mac_key.as_slice()))
        .compute_unpadded(&data)
        .to_vec();
    out.extend(data);
    out
}

/// The scrypt cost of the keys made here: what `skopeo
/// generate-sigstore-key` and `cosign generate-key-pair` (3) write.
const SCRYPT_N: u64 = 1 << 16;

/// A new ECDSA P-256 key pair, as `cosign generate-key-pair` and `skopeo
/// generate-sigstore-key` make it: the private key as the PEM that
/// [`Signer::load`] reads (the PKCS#8 key sealed with the NaCl secretbox
/// under the scrypt key of `passphrase`) and the public key as a PEM
/// `PUBLIC KEY`.  The salt and the nonce come from the CSPRNG of OpenSSL.
pub fn generate_key_pair(passphrase: &[u8]) -> Result<(Zeroizing<String>, String), Error> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let ssl = |e: openssl::error::ErrorStack| Error(format!("generating the key: {e}"));
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(ssl)?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(ssl)?).map_err(ssl)?;
    let public = String::from_utf8(key.public_key_to_pem().map_err(ssl)?)
        .map_err(|_| Error("the public key is not PEM".into()))?;
    let der = Zeroizing::new(key.private_key_to_pkcs8().map_err(ssl)?);
    Ok((seal_key(&der, passphrase, SCRYPT_N)?, public))
}

/// The PEM of the PKCS#8 key `der` sealed under the scrypt key (cost `n`)
/// of `passphrase`.
fn seal_key(der: &[u8], passphrase: &[u8], n: u64) -> Result<Zeroizing<String>, Error> {
    let ssl = |e: openssl::error::ErrorStack| Error(format!("generating the key: {e}"));
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    openssl::rand::rand_bytes(&mut salt).map_err(ssl)?;
    openssl::rand::rand_bytes(&mut nonce).map_err(ssl)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    openssl::pkcs5::scrypt(
        passphrase,
        &salt,
        n,
        8,
        1,
        MAX_SCRYPT_MEMORY * 2,
        secret.as_mut_slice(),
    )
    .map_err(|e| Error(format!("scrypt: {e}")))?;
    let envelope = Envelope {
        kdf: Kdf {
            name: "scrypt".into(),
            params: ScryptParams { n, r: 8, p: 1 },
            salt: salt.to_vec(),
        },
        cipher: Cipher {
            name: "nacl/secretbox".into(),
            nonce: nonce.to_vec(),
        },
        ciphertext: secretbox_seal(&secret, &nonce, der),
    };
    let json = Zeroizing::new(
        serde_json::to_vec(&envelope).map_err(|e| Error(format!("encoding the key: {e}")))?,
    );
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*json));
    let mut pem = Zeroizing::new(String::with_capacity(b64.len() + b64.len() / 32 + 128));
    pem.push_str("-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END ENCRYPTED COSIGN PRIVATE KEY-----\n");
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    /// The box of the NaCl test vectors (`tests/secretbox.c` of NaCl, the
    /// 131 bytes of the message under the key and nonce of `firstkey`).
    #[test]
    fn secretbox_opens_the_nacl_vector() {
        let key: [u8; 32] =
            unhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = unhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
            .try_into()
            .unwrap();
        let plain = unhex(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc
             e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31
             0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde
             048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864
             5e0705",
        );
        let boxed = unhex(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce
             48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972
             71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae
             90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3
             7973f622a43d14a6599b1f654cb45a74e355a5",
        );
        assert_eq!(
            secretbox_open(&key, &nonce, &boxed).unwrap().as_slice(),
            plain
        );
        assert_eq!(secretbox_seal(&key, &nonce, &plain), boxed);
    }

    #[test]
    fn secretbox_round_trips_and_detects_changes() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        for len in [0usize, 1, 31, 32, 33, 63, 64, 65, 200] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let boxed = secretbox_seal(&key, &nonce, &plain);
            assert_eq!(
                secretbox_open(&key, &nonce, &boxed).as_deref(),
                Some(&plain),
                "{len}"
            );
            let mut bad = boxed.clone();
            *bad.last_mut().unwrap_or(&mut 0) ^= 1;
            if len > 0 {
                assert!(secretbox_open(&key, &nonce, &bad).is_none());
            }
        }
        assert!(secretbox_open(&key, &nonce, &[0u8; 15]).is_none());
    }

    /// A key made by `skopeo generate-sigstore-key` (passphrase `secret`).
    const SKOPEO_KEY: &str = "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJ2V1pEcTlQNUFLemZ0V0JhYjBhZzlCY1BHM2cva3ht
RGZSdUhNNG5MdUlZPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJnSlJ5MjJJYzRrNUdYS0pmT1JUVGFtb0JFQi9aNU0vZiJ9LCJj
aXBoZXJ0ZXh0IjoiRzk3ZWZTUXhjQlNBdEFWOUQ3VXZmOGdKckw0a1pNTitSMnBi
T2lydUNLTVB4VlZ6OFlNUW0wOThIamNqMEZnVCsyZnBVOU5zT012MDA5b0tQbnFt
ZUxrU1pLcnZ1N0QrQlZoMXFYRHBUcGx3N0VLWHNXRFZjNVVCWW1JSys1Vll6K1Jm
R3Qya25HZzQ3WXRUQXNKQVRnQ1dCYkprb3BLb0NNQzJHQlJpRGxVMk9YWEdGUTNk
WDdpbXJsR1pqUi9hQ1VMTXE2aGdsTGdXeFE9PSJ9
-----END ENCRYPTED COSIGN PRIVATE KEY-----
";
    const SKOPEO_PUB: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjRMvLZLP+3IgpEbDgdtuZjXJ7pLb
QSGFaQFE7Zydj1mCzfDh04I5w3jAN/qNAPyq+1IDO890Q8MinNL9NNNEuQ==
-----END PUBLIC KEY-----
";

    fn files(pass: &str) -> KeyFiles {
        KeyFiles {
            key: SKOPEO_KEY.as_bytes().to_vec(),
            passphrase: pass.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_key_of_skopeo_loads_and_signs_what_its_public_key_verifies() {
        let signer = Signer::load(&files("secret")).unwrap();
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sig = signer
            .sign_manifest(digest, "localhost:5000/a/b:1", "velarx test", 1_700_000_000)
            .unwrap();
        assert_eq!(sig.mime_type, SIGSTORE_MEDIA_TYPE);
        let root = crate::sigstore::TrustRoot {
            public_keys: vec![crate::sigstore::public_key_from_pem(SKOPEO_PUB.as_bytes()).unwrap()],
            ..Default::default()
        };
        let payload = root.verify(&sig, 1_700_000_000).unwrap();
        assert_eq!(payload.manifest_digest, digest);
        assert_eq!(payload.docker_reference, "localhost:5000/a/b:1");
        // another key does not verify it
        let other = crate::sigstore::tests::ec_key();
        let root = crate::sigstore::TrustRoot {
            public_keys: vec![
                PKey::public_key_from_der(&other.public_key_to_der().unwrap()).unwrap(),
            ],
            ..Default::default()
        };
        assert!(root.verify(&sig, 1_700_000_000).is_err());
    }

    #[test]
    fn a_wrong_passphrase_or_a_foreign_key_is_refused() {
        let e = Signer::load(&files("wrong")).unwrap_err().to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        let plain = KeyFiles {
            key: SKOPEO_PUB.as_bytes().to_vec(),
            passphrase: Vec::new(),
        };
        let e = Signer::load(&plain).unwrap_err().to_string();
        assert!(e.contains("unsupported private key type"), "{e}");
        let e = format!("{:?}", files("secret"));
        assert!(!e.contains("secret") && !e.contains("COSIGN"));
    }

    #[test]
    fn scrypt_parameters_are_bounded() {
        let doc = |n: u64| {
            let json = format!(
                r#"{{"kdf":{{"name":"scrypt","params":{{"N":{n},"r":8,"p":1}},"salt":"AAAA"}},"cipher":{{"name":"nacl/secretbox","nonce":"{}"}},"ciphertext":"AAAA"}}"#,
                base64::engine::general_purpose::STANDARD.encode([0u8; 24])
            );
            format!(
                "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n{}\n-----END ENCRYPTED COSIGN PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(json)
            )
        };
        let e = decrypt_key(doc(1 << 40).as_bytes(), b"x")
            .unwrap_err()
            .to_string();
        assert!(e.contains("too much memory"), "{e}");
        let e = decrypt_key(doc(3).as_bytes(), b"x")
            .unwrap_err()
            .to_string();
        assert!(e.contains("invalid scrypt"), "{e}");
    }

    #[test]
    fn a_generated_key_loads_signs_and_its_public_key_verifies() {
        let (private, public) = generate_key_pair(b"hunter2").unwrap();
        assert!(private.starts_with("-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n"));
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let load = |pass: &[u8]| {
            Signer::load(&KeyFiles {
                key: private.as_bytes().to_vec(),
                passphrase: pass.to_vec(),
            })
        };
        let e = load(b"other").unwrap_err().to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        let signer = load(b"hunter2").unwrap();
        let sig = signer
            .sign_manifest("sha256:abcd", "example.com/a/b:1", "velarx", 0)
            .unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&sig.annotations[SIGNATURE_ANNOTATION])
            .unwrap();
        let pubkey = PKey::public_key_from_pem(public.as_bytes()).unwrap();
        let mut v = openssl::sign::Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        assert!(v.verify_oneshot(&der, &sig.payload).unwrap());
        // another key does not verify it
        let (_, other) = generate_key_pair(b"x").unwrap();
        let pubkey = PKey::public_key_from_pem(other.as_bytes()).unwrap();
        let mut v = openssl::sign::Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        assert!(!v.verify_oneshot(&der, &sig.payload).unwrap());
    }

    /// The cost cosign wrote before it wrote that of skopeo.
    #[test]
    fn a_key_of_a_lower_scrypt_cost_loads() {
        let key = crate::sigstore::tests::ec_key();
        let der = key.private_key_to_pkcs8().unwrap();
        let pem = seal_key(&der, b"pw", 1 << 15).unwrap();
        let signer = Signer::load(&KeyFiles {
            key: pem.as_bytes().to_vec(),
            passphrase: b"pw".to_vec(),
        })
        .unwrap();
        assert!(signer.key.public_eq(&key));
    }

    #[test]
    fn generated_keys_differ_and_an_empty_passphrase_works() {
        let (a, pa) = generate_key_pair(b"").unwrap();
        let (b, pb) = generate_key_pair(b"").unwrap();
        assert_ne!(*a, *b);
        assert_ne!(pa, pb);
        Signer::load(&KeyFiles {
            key: a.as_bytes().to_vec(),
            passphrase: Vec::new(),
        })
        .unwrap();
    }
}
