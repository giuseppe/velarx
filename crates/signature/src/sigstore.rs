// SPDX-License-Identifier: Apache-2.0
//! Sigstore signatures as containers/image verifies them: cosign
//! attachments and the `sigstore-json` blobs of lookaside storage, signed
//! by a public key, by a Fulcio certificate logged in Rekor, or by a
//! certificate of a private PKI; and the payload both signature formats
//! share (`critical`/`optional`).
//!
//! The cryptography and the certificate chains are OpenSSL's.  Everything
//! here but the trust roots comes from an untrusted signature.

use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Public};
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};
use std::collections::BTreeMap;

pub const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
pub const CERTIFICATE_ANNOTATION: &str = "dev.sigstore.cosign/certificate";
pub const CHAIN_ANNOTATION: &str = "dev.sigstore.cosign/chain";
pub const SET_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
/// The media type of a cosign signature layer.
pub const SIGSTORE_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";

/// The `type` of the payload of a simple signing signature.
pub const SIMPLE_SIGNING_TYPE: &str = "atomic container signature";
/// The `type` of the payload of a sigstore signature.
pub const SIGSTORE_TYPE: &str = "cosign container image signature";

/// Largest signature blob or payload read.
pub const MAX_SIGNATURE_SIZE: u64 = 4 << 20;

/// Why a signature is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

fn ssl(e: openssl::error::ErrorStack) -> Error {
    Error(e.to_string())
}

/// A sigstore signature: its media type, its payload, the annotations
/// that carry the signature, the certificate, the Rekor bundle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sigstore {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// A signature of an image, in one of the two formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// An OpenPGP signed message (simple signing).
    Simple(Vec<u8>),
    Sigstore(Sigstore),
}

impl Signature {
    /// A signature of lookaside storage: an OpenPGP message as is, or a
    /// NUL, the name of the format, a newline and the format's bytes.
    pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
        match blob.first() {
            None => err("an empty signature"),
            // the first byte of a compressed data, one-pass signature or
            // signature packet
            Some(0xA0..=0xA3 | 0xC8 | 0x90..=0x92 | 0x3d | 0xC4 | 0x88..=0x8B | 0xC2) => {
                Ok(Signature::Simple(blob.to_vec()))
            }
            Some(0) => {
                let rest = &blob[1..];
                let nl = rest
                    .iter()
                    .position(|b| *b == b'\n')
                    .ok_or_else(|| Error("invalid signature format, missing newline".into()))?;
                let (format, chunk) = (&rest[..nl], &rest[nl + 1..]);
                match format {
                    b"simple-signing" => Ok(Signature::Simple(chunk.to_vec())),
                    b"sigstore-json" => serde_json::from_slice(chunk)
                        .map(Signature::Sigstore)
                        .map_err(|e| Error(format!("invalid sigstore signature: {e}"))),
                    _ => err(format!(
                        "unrecognized signature format {:?}",
                        String::from_utf8_lossy(format)
                    )),
                }
            }
            Some(b) => err(format!(
                "unrecognized signature format, starting with {b:#x}"
            )),
        }
    }

    /// The blob of lookaside storage, as `from_blob` reads it back.
    pub fn to_blob(&self) -> Vec<u8> {
        match self {
            Signature::Simple(b) => b.clone(),
            Signature::Sigstore(s) => {
                let mut out = b"\0sigstore-json\n".to_vec();
                out.extend(serde_json::to_vec(s).unwrap_or_default());
                out
            }
        }
    }
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

/// What a signature says once verified: the manifest it signs, and the
/// reference the signer gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub manifest_digest: String,
    pub docker_reference: String,
    /// When it was signed (seconds since the epoch), as the signer wrote
    /// it; 0 when it did not.
    pub timestamp: i64,
}

/// The fields of the JSON object `v`, which must be exactly `names`.
fn exact<'a>(
    v: &'a serde_json::Value,
    names: &[&str],
    what: &str,
) -> Result<Vec<&'a serde_json::Value>, Error> {
    let obj = v
        .as_object()
        .ok_or_else(|| Error(format!("{what} is not a JSON object")))?;
    if obj.len() != names.len() || !names.iter().all(|n| obj.contains_key(*n)) {
        return err(format!(
            "{what} must have exactly the fields {}",
            names.join(", ")
        ));
    }
    Ok(names.iter().map(|n| &obj[*n]).collect())
}

fn string<'a>(v: &'a serde_json::Value, what: &str) -> Result<&'a str, Error> {
    v.as_str()
        .ok_or_else(|| Error(format!("{what} is not a string")))
}

/// The payload of a signature of type `kind`, as containers/image reads
/// it: `critical` and `optional` only, `critical` with exactly its type,
/// image and identity.
pub fn parse_payload(data: &[u8], kind: &str) -> Result<Payload, Error> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| Error(format!("invalid signature payload: {e}")))?;
    let [critical, optional] = exact(&v, &["critical", "optional"], "the payload")?[..] else {
        return err("invalid signature payload");
    };
    // (cosign writes `"optional":null` when it has nothing to add, which
    // containers/image reads as an empty object)
    if !optional.is_object() && !optional.is_null() {
        return err("`optional` is not a JSON object");
    }
    let mut timestamp = 0;
    if let Some(t) = optional.get("timestamp") {
        // (a JSON number of integral value, 1.7e9 too, as containers/image
        // reads it into a float)
        timestamp = match (t.as_i64(), t.as_f64()) {
            (Some(i), _) => i,
            (None, Some(f)) if f.fract() == 0.0 && f.abs() < 9.2e18 => f as i64,
            _ => return err("`optional.timestamp` is not an integer"),
        };
    }
    if optional.get("creator").is_some_and(|c| !c.is_string()) {
        return err("`optional.creator` is not a string");
    }
    let [t, image, identity] = exact(critical, &["type", "image", "identity"], "`critical`")?[..]
    else {
        return err("invalid signature payload");
    };
    let t = string(t, "`critical.type`")?;
    if t != kind {
        return err(format!("unrecognized signature type {t:?}"));
    }
    let [d] = exact(image, &["docker-manifest-digest"], "`critical.image`")?[..] else {
        return err("invalid signature payload");
    };
    let manifest_digest = string(d, "the manifest digest")?.to_string();
    if digest_algorithm(&manifest_digest).is_none() {
        return err(format!(
            "invalid docker-manifest-digest {manifest_digest:?}"
        ));
    }
    let [r] = exact(identity, &["docker-reference"], "`critical.identity`")?[..] else {
        return err("invalid signature payload");
    };
    Ok(Payload {
        manifest_digest,
        docker_reference: string(r, "the docker reference")?.to_string(),
        timestamp,
    })
}

/// The hash of a digest `ALGO:HEX`, when it is a valid one.
fn digest_algorithm(digest: &str) -> Option<MessageDigest> {
    let (algo, hex) = digest.split_once(':')?;
    let (md, len) = match algo {
        "sha256" => (MessageDigest::sha256(), 64),
        "sha384" => (MessageDigest::sha384(), 96),
        "sha512" => (MessageDigest::sha512(), 128),
        _ => return None,
    };
    (hex.len() == len
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(md)
}

/// Whether `digest` (`ALGO:HEX`) is the digest of `manifest`, with the
/// algorithm it names.
pub fn manifest_matches(manifest: &[u8], digest: &str) -> bool {
    let Some(md) = digest_algorithm(digest) else {
        return false;
    };
    let Ok(d) = openssl::hash::hash(md, manifest) else {
        return false;
    };
    digest.split_once(':').map(|(_, h)| h) == Some(hex::encode(d).as_str())
}

/// A PEM public key (SubjectPublicKeyInfo, or PKCS#1 RSA).
pub fn public_key_from_pem(pem: &[u8]) -> Result<PKey<Public>, Error> {
    if let Ok(k) = PKey::public_key_from_pem(pem) {
        return Ok(k);
    }
    openssl::rsa::Rsa::public_key_from_pem_pkcs1(pem)
        .and_then(PKey::from_rsa)
        .map_err(|_| Error("invalid public key: not a PEM public key".into()))
}

/// Whether `sig` is a signature of `data` by `key`, as sigstore makes
/// them: SHA-256 with ECDSA or RSA PKCS#1 v1.5, or Ed25519.
fn verify_with(key: &PKey<Public>, data: &[u8], sig: &[u8]) -> bool {
    let check = || -> Result<bool, openssl::error::ErrorStack> {
        if key.id() == Id::ED25519 {
            let mut v = Verifier::new_without_digest(key)?;
            return v.verify_oneshot(sig, data);
        }
        let mut v = Verifier::new(MessageDigest::sha256(), key)?;
        v.update(data)?;
        v.verify(sig)
    };
    check().unwrap_or(false)
}

/// One PEM block of `data` and nothing else: its label and its DER.
fn pem_one(data: &[u8]) -> Result<(String, Vec<u8>), Error> {
    let text = std::str::from_utf8(data).map_err(|_| Error("PEM data is not text".into()))?;
    let text = text.trim();
    let first = text.lines().next().unwrap_or_default();
    let label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or_else(|| Error("not in PEM format".into()))?;
    let end = format!("-----END {label}-----");
    let body_end = text
        .find(&end)
        .ok_or_else(|| Error("PEM without its end".into()))?;
    if !text[body_end + end.len()..].trim().is_empty() {
        return err("PEM data with trailing data");
    }
    let body: String = text[first.len()..body_end]
        .lines()
        .map(str::trim)
        .filter(|l| !l.contains(':'))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| Error("invalid base64 in PEM data".into()))?;
    Ok((label.to_string(), der))
}

/// The certificates of PEM data.
fn certificates(pem: &[u8]) -> Result<Vec<X509>, Error> {
    let certs = X509::stack_from_pem(pem).map_err(|_| Error("invalid certificates".into()))?;
    if certs.is_empty() {
        return err("no certificate found");
    }
    Ok(certs)
}

/// The trust roots of a `sigstoreSigned` requirement.
#[derive(Default)]
pub struct TrustRoot {
    pub public_keys: Vec<PKey<Public>>,
    pub fulcio: Option<Fulcio>,
    pub rekor_keys: Vec<PKey<Public>>,
    pub pki: Option<Pki>,
}

pub struct Fulcio {
    pub ca: Vec<X509>,
    pub oidc_issuer: String,
    pub subject_email: String,
}

pub struct Pki {
    pub roots: Vec<X509>,
    pub intermediates: Vec<X509>,
    pub subject_email: Option<String>,
    pub subject_hostname: Option<String>,
}

impl TrustRoot {
    /// Read PEM public keys, CA certificates, the issuer and the email of
    /// the requirement; `fulcio` and `pki` are checked as containers/image
    /// does: one source of keys, and Rekor with Fulcio, not with a PKI.
    pub fn check(&self) -> Result<(), Error> {
        let sources = usize::from(!self.public_keys.is_empty())
            + usize::from(self.fulcio.is_some())
            + usize::from(self.pki.is_some());
        if sources != 1 {
            return err(
                "a sigstoreSigned requirement needs exactly one of public keys, Fulcio and a PKI",
            );
        }
        if self.fulcio.is_some() && self.rekor_keys.is_empty() {
            return err("a sigstoreSigned requirement with Fulcio needs a Rekor public key");
        }
        if self.pki.is_some() && !self.rekor_keys.is_empty() {
            return err("a sigstoreSigned requirement with a PKI cannot have a Rekor public key");
        }
        if let Some(f) = &self.fulcio {
            if f.oidc_issuer.is_empty() || f.subject_email.is_empty() {
                return err("Fulcio needs an OIDC issuer and a subject email");
            }
        }
        if let Some(p) = &self.pki {
            if p.subject_email.is_none() && p.subject_hostname.is_none() {
                return err("a PKI needs a subject email or a subject hostname");
            }
        }
        if self.rekor_keys.iter().any(|k| k.id() != Id::EC) {
            return err("Rekor public keys must be ECDSA keys");
        }
        Ok(())
    }

    /// The payload of `sig`, when it is a signature these roots accept.
    /// `now`: seconds since the epoch, for a PKI certificate.
    pub fn verify(&self, sig: &Sigstore, now: i64) -> Result<Payload, Error> {
        self.check()?;
        let b64sig = sig
            .annotations
            .get(SIGNATURE_ANNOTATION)
            .ok_or_else(|| Error(format!("missing {SIGNATURE_ANNOTATION} annotation")))?;
        let raw_sig = base64::engine::general_purpose::STANDARD
            .decode(b64sig.as_bytes())
            .map_err(|_| Error("the signature is not base64".into()))?;
        let keys: Vec<PKey<Public>> = if !self.public_keys.is_empty() {
            if self.rekor_keys.is_empty() {
                self.public_keys.clone()
            } else {
                let set = sig
                    .annotations
                    .get(SET_ANNOTATION)
                    .ok_or_else(|| Error(format!("missing {SET_ANNOTATION} annotation")))?;
                let mut why = Vec::new();
                let mut found = None;
                for k in &self.public_keys {
                    let der = k.public_key_to_der().map_err(ssl)?;
                    match verify_rekor_set(
                        &self.rekor_keys,
                        set.as_bytes(),
                        &der,
                        &raw_sig,
                        &sig.payload,
                    ) {
                        Ok(_) => {
                            found = Some(k.clone());
                            break;
                        }
                        Err(e) => why.push(e.0),
                    }
                }
                match found {
                    Some(k) => vec![k],
                    None => {
                        return err(format!(
                            "no public key verified against the Rekor SET: {}",
                            why.join(", ")
                        ))
                    }
                }
            }
        } else if let Some(f) = &self.fulcio {
            let set = sig
                .annotations
                .get(SET_ANNOTATION)
                .ok_or_else(|| Error(format!("missing {SET_ANNOTATION} annotation")))?;
            let cert_pem = sig
                .annotations
                .get(CERTIFICATE_ANNOTATION)
                .ok_or_else(|| Error(format!("missing {CERTIFICATE_ANNOTATION} annotation")))?;
            let (_, cert_der) = pem_one(cert_pem.as_bytes())?;
            let time = verify_rekor_set(
                &self.rekor_keys,
                set.as_bytes(),
                &cert_der,
                &raw_sig,
                &sig.payload,
            )?;
            let chain = sig.annotations.get(CHAIN_ANNOTATION);
            vec![f.verify_certificate(time, cert_pem.as_bytes(), chain.map(|c| c.as_bytes()))?]
        } else if let Some(p) = &self.pki {
            let cert_pem = sig
                .annotations
                .get(CERTIFICATE_ANNOTATION)
                .ok_or_else(|| Error(format!("missing {CERTIFICATE_ANNOTATION} annotation")))?;
            let chain = sig.annotations.get(CHAIN_ANNOTATION);
            vec![p.verify_certificate(now, cert_pem.as_bytes(), chain.map(|c| c.as_bytes()))?]
        } else {
            return err("no trust root");
        };
        if !keys.iter().any(|k| verify_with(k, &sig.payload, &raw_sig)) {
            return err("cryptographic signature verification failed");
        }
        parse_payload(&sig.payload, SIGSTORE_TYPE)
    }
}

/// The leaf certificate of PEM data that must have exactly one, and the
/// certificates of a chain annotation but its last (the root, which must
/// come from the trust root).
fn leaf_and_chain(cert_pem: &[u8], chain_pem: Option<&[u8]>) -> Result<(X509, Stack<X509>), Error> {
    let mut leaf = certificates(cert_pem)?;
    if leaf.len() != 1 {
        return err("unexpected multiple certificates in the signature certificate");
    }
    let mut stack = Stack::new().map_err(ssl)?;
    if let Some(c) = chain_pem.filter(|c| !c.is_empty()) {
        let mut certs = certificates(c)?;
        certs.pop();
        for cert in certs {
            stack.push(cert).map_err(ssl)?;
        }
    }
    Ok((leaf.remove(0), stack))
}

/// Whether `leaf` chains to `roots` through `chain` at `time`, for code
/// signing, and has `hostname` when it is given.
fn verify_chain(
    leaf: &X509,
    chain: &Stack<X509>,
    roots: &[X509],
    time: i64,
    hostname: Option<&str>,
) -> Result<(), Error> {
    let mut store = X509StoreBuilder::new().map_err(ssl)?;
    for r in roots {
        store.add_cert(r.clone()).map_err(ssl)?;
    }
    let mut param = openssl::x509::verify::X509VerifyParam::new().map_err(ssl)?;
    param.set_time(time as libc::time_t);
    if let Some(h) = hostname {
        // the subject alternative names only, never the common name
        param.set_hostflags(openssl::x509::verify::X509CheckFlags::NEVER_CHECK_SUBJECT);
        param.set_host(h).map_err(ssl)?;
    }
    store.set_param(&param).map_err(ssl)?;
    let store = store.build();
    let mut ctx = X509StoreContext::new().map_err(ssl)?;
    let (ok, result) = ctx
        .init(&store, leaf, chain, |c| Ok((c.verify_cert()?, c.error())))
        .map_err(ssl)?;
    if !ok || result != X509VerifyResult::OK {
        return err(format!(
            "verifying the leaf certificate failed: {}",
            result.error_string()
        ));
    }
    // the extended key usage, which OpenSSL does not check for code signing
    let exts = extensions(&leaf.to_der().map_err(ssl)?)?;
    if let Some((_, _, eku)) = exts.iter().find(|(oid, _, _)| oid == OID_EKU) {
        let usages = der_sequence_items(eku)?;
        if !usages
            .iter()
            .any(|u| u == OID_CODE_SIGNING || u == OID_ANY_EKU)
        {
            return err("the certificate is not for code signing");
        }
    }
    Ok(())
}

fn emails(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.email().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

impl Fulcio {
    fn verify_certificate(
        &self,
        time: i64,
        cert_pem: &[u8],
        chain_pem: Option<&[u8]>,
    ) -> Result<PKey<Public>, Error> {
        let (leaf, chain) = leaf_and_chain(cert_pem, chain_pem)?;
        verify_chain(&leaf, &chain, &self.ca, time, None)?;
        let issuer = fulcio_issuer(&leaf.to_der().map_err(ssl)?)?;
        if issuer != self.oidc_issuer {
            return err(format!("unexpected Fulcio OIDC issuer {issuer:?}"));
        }
        let got = emails(&leaf);
        if !got.contains(&self.subject_email) {
            return err(format!(
                "required email {:?} not found (got {got:?})",
                self.subject_email
            ));
        }
        leaf.public_key().map_err(ssl)
    }
}

impl Pki {
    fn verify_certificate(
        &self,
        now: i64,
        cert_pem: &[u8],
        chain_pem: Option<&[u8]>,
    ) -> Result<PKey<Public>, Error> {
        let (leaf, mut chain) = leaf_and_chain(cert_pem, chain_pem)?;
        for c in &self.intermediates {
            chain.push(c.clone()).map_err(ssl)?;
        }
        verify_chain(
            &leaf,
            &chain,
            &self.roots,
            now,
            self.subject_hostname.as_deref(),
        )?;
        if let Some(e) = &self.subject_email {
            let got = emails(&leaf);
            if !got.contains(e) {
                return err(format!("required email {e:?} not found (got {got:?})"));
            }
        }
        leaf.public_key().map_err(ssl)
    }
}

// DER: the extensions of a certificate, which the openssl crate does not
// give by OID.

/// 1.3.6.1.4.1.57264.1.1, Fulcio's OIDC issuer (v1, the raw string).
const OID_FULCIO_ISSUER_V1: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x01];
/// 1.3.6.1.4.1.57264.1.8, Fulcio's OIDC issuer (v2, a DER UTF8String).
const OID_FULCIO_ISSUER_V2: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x08];
/// 2.5.29.37, the extended key usage.
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// The tag, the content and the rest of the DER element at the start of
/// `data`.
fn der(data: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let bad = || Error("invalid DER in the certificate".into());
    let (&tag, rest) = data.split_first().ok_or_else(bad)?;
    let (&l, rest) = rest.split_first().ok_or_else(bad)?;
    let (len, rest) = if l < 0x80 {
        (usize::from(l), rest)
    } else {
        let n = usize::from(l & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return Err(bad());
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(bad());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

/// The contents of the elements of a DER SEQUENCE.
fn der_sequence_items(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let (tag, mut content, _) = der(data)?;
    if tag != 0x30 {
        return err("invalid DER sequence");
    }
    let mut out = Vec::new();
    while !content.is_empty() {
        let (_, item, rest) = der(content)?;
        out.push(item.to_vec());
        content = rest;
    }
    Ok(out)
}

/// An extension of a certificate: its OID, whether it is critical, its
/// value.
type Extension = (Vec<u8>, bool, Vec<u8>);

/// The extensions of a DER certificate.
fn extensions(cert: &[u8]) -> Result<Vec<Extension>, Error> {
    let (_, cert, _) = der(cert)?;
    let (_, mut tbs, _) = der(cert)?;
    let mut out = Vec::new();
    while !tbs.is_empty() {
        let (tag, content, rest) = der(tbs)?;
        tbs = rest;
        // [3] EXPLICIT Extensions
        if tag != 0xa3 {
            continue;
        }
        let (_, mut list, _) = der(content)?;
        while !list.is_empty() {
            let (_, ext, rest) = der(list)?;
            list = rest;
            let (_, oid, mut ext) = der(ext)?;
            let mut critical = false;
            let (t, c, r) = der(ext)?;
            let value = if t == 0x01 {
                critical = c == [0xff];
                ext = r;
                der(ext)?.1
            } else {
                c
            };
            out.push((oid.to_vec(), critical, value.to_vec()));
        }
    }
    Ok(out)
}

/// The OIDC issuer of a Fulcio certificate, from either extension (both
/// must agree).
fn fulcio_issuer(cert: &[u8]) -> Result<String, Error> {
    let mut v1 = None;
    let mut v2 = None;
    for (oid, _, value) in extensions(cert)? {
        if oid == OID_FULCIO_ISSUER_V1 {
            if v1.is_some() {
                return err("a duplicate OIDC issuer v1 extension");
            }
            v1 =
                Some(String::from_utf8(value).map_err(|_| Error("an invalid OIDC issuer".into()))?);
        } else if oid == OID_FULCIO_ISSUER_V2 {
            if v2.is_some() {
                return err("a duplicate OIDC issuer v2 extension");
            }
            let (tag, s, rest) = der(&value)?;
            if tag != 0x0c || !rest.is_empty() {
                return err("an invalid OIDC issuer v2 extension");
            }
            v2 = Some(
                String::from_utf8(s.to_vec())
                    .map_err(|_| Error("an invalid OIDC issuer".into()))?,
            );
        }
    }
    match (v1, v2) {
        (Some(a), Some(b)) if a != b => err(format!("inconsistent OIDC issuers {a:?} and {b:?}")),
        (Some(a), _) | (None, Some(a)) => Ok(a),
        (None, None) => err("the Fulcio certificate has no OIDC issuer"),
    }
}

/// JSON canonicalized as RFC 8785 says, for what a Rekor SET payload has:
/// objects, arrays, strings, booleans, null and integers.
pub fn canonical_json(v: &serde_json::Value, out: &mut String) -> Result<(), Error> {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return err("a JSON number that is not an integer");
            }
        }
        Value::String(s) => canonical_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(x, out)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            // by UTF-16 code units
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_string(k, out);
                out.push(':');
                canonical_json(&o[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn canonical_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn b64_field(v: &serde_json::Value, what: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::STANDARD
        .decode(string(v, what)?.as_bytes())
        .map_err(|_| Error(format!("{what} is not base64")))
}

/// Verify the Rekor SET (`bundle` annotation) of a signature: signed by
/// one of `rekor_keys`, logging `key_der` (the DER of the public key or of
/// the certificate), `sig` and the SHA-256 of `payload`.  The time it was
/// logged at.
pub fn verify_rekor_set(
    rekor_keys: &[PKey<Public>],
    set: &[u8],
    key_der: &[u8],
    sig: &[u8],
    payload: &[u8],
) -> Result<i64, Error> {
    let v: serde_json::Value =
        serde_json::from_slice(set).map_err(|e| Error(format!("invalid Rekor SET: {e}")))?;
    let [set_sig, set_payload] =
        exact(&v, &["SignedEntryTimestamp", "Payload"], "the Rekor SET")?[..]
    else {
        return err("invalid Rekor SET");
    };
    let set_sig = b64_field(set_sig, "the Rekor SET signature")?;
    let mut canonical = String::new();
    canonical_json(set_payload, &mut canonical)?;
    let signed = rekor_keys.iter().any(|k| {
        let check = || -> Result<bool, openssl::error::ErrorStack> {
            let mut v = Verifier::new(MessageDigest::sha256(), k)?;
            v.update(canonical.as_bytes())?;
            v.verify(&set_sig)
        };
        check().unwrap_or(false)
    });
    if !signed {
        return err("cryptographic signature verification of the Rekor SET failed");
    }
    let [body, time, _index, _id] = exact(
        set_payload,
        &["body", "integratedTime", "logIndex", "logID"],
        "the Rekor SET payload",
    )?[..] else {
        return err("invalid Rekor SET");
    };
    let time = time
        .as_i64()
        .ok_or_else(|| Error("the integrated time is not an integer".into()))?;
    let body = b64_field(body, "the Rekor entry")?;
    let entry: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Error(format!("invalid Rekor entry: {e}")))?;
    if entry.get("kind").and_then(|k| k.as_str()) != Some("hashedrekord") {
        return err("the Rekor entry is not a hashedrekord");
    }
    if entry.get("apiVersion").and_then(|k| k.as_str()) != Some("0.0.1") {
        return err("unsupported version of the hashedrekord");
    }
    let spec = &entry["spec"];
    let logged_key = b64_field(
        &spec["signature"]["publicKey"]["content"],
        "the logged public key",
    )?;
    let (_, logged_der) = pem_one(&logged_key)?;
    if logged_der != key_der {
        return err("the public key in the Rekor SET does not match");
    }
    if b64_field(&spec["signature"]["content"], "the logged signature")? != sig {
        return err("the signature in the Rekor SET does not match");
    }
    let hash = &spec["data"]["hash"];
    if hash["algorithm"].as_str() != Some("sha256") {
        return err("unexpected hash algorithm in the Rekor SET");
    }
    let logged = hex::decode(string(&hash["value"], "the logged hash")?)
        .map_err(|_| Error("invalid hash in the Rekor SET".into()))?;
    let actual = openssl::hash::hash(MessageDigest::sha256(), payload).map_err(ssl)?;
    if logged != actual.as_ref() {
        return err("the payload in the Rekor SET does not match");
    }
    Ok(time)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::Private;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    pub const DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TIME: i64 = 1_791_700_000;

    pub fn ec_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    pub fn sign(key: &PKey<Private>, data: &[u8]) -> Vec<u8> {
        let mut s = openssl::sign::Signer::new(MessageDigest::sha256(), key).unwrap();
        s.update(data).unwrap();
        s.sign_to_vec().unwrap()
    }

    pub fn payload(kind: &str, reference: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": {"docker-reference": reference},
                "image": {"docker-manifest-digest": DIGEST},
                "type": kind,
            },
            "optional": {"creator": "test"},
        }))
        .unwrap()
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// A signature of `payload` by `key`, with a Rekor SET logging
    /// `logged_pem` when `rekor` is given.
    pub fn signature(
        key: &PKey<Private>,
        payload: &[u8],
        rekor: Option<(&PKey<Private>, &[u8])>,
    ) -> Sigstore {
        let sig = sign(key, payload);
        let mut annotations = BTreeMap::new();
        annotations.insert(SIGNATURE_ANNOTATION.to_string(), b64(&sig));
        if let Some((rk, logged_pem)) = rekor {
            annotations.insert(
                SET_ANNOTATION.to_string(),
                rekor_set(rk, logged_pem, &sig, payload, TIME),
            );
        }
        Sigstore {
            mime_type: SIGSTORE_MEDIA_TYPE.into(),
            payload: payload.to_vec(),
            annotations,
        }
    }

    fn rekor_set(
        rk: &PKey<Private>,
        logged_pem: &[u8],
        sig: &[u8],
        payload: &[u8],
        time: i64,
    ) -> String {
        let hash = openssl::hash::hash(MessageDigest::sha256(), payload).unwrap();
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": hex::encode(hash)}},
                "signature": {"content": b64(sig), "publicKey": {"content": b64(logged_pem)}},
            },
        });
        let p = serde_json::json!({
            "body": b64(body.to_string().as_bytes()),
            "integratedTime": time,
            "logIndex": 7,
            "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
        });
        let mut canonical = String::new();
        canonical_json(&p, &mut canonical).unwrap();
        serde_json::json!({
            "SignedEntryTimestamp": b64(&sign(rk, canonical.as_bytes())),
            "Payload": p,
        })
        .to_string()
    }

    fn public(k: &PKey<Private>) -> PKey<Public> {
        PKey::public_key_from_der(&k.public_key_to_der().unwrap()).unwrap()
    }

    fn pem(k: &PKey<Private>) -> Vec<u8> {
        k.public_key_to_pem().unwrap()
    }

    #[test]
    fn payloads_are_read_paranoidly() {
        let p = parse_payload(&payload(SIGSTORE_TYPE, "a/b:c"), SIGSTORE_TYPE).unwrap();
        assert_eq!(p.manifest_digest, DIGEST);
        assert_eq!(p.docker_reference, "a/b:c");
        assert!(parse_payload(&payload(SIMPLE_SIGNING_TYPE, "a"), SIGSTORE_TYPE).is_err());
        let null_optional = format!(
            r#"{{"critical":{{"type":"{SIGSTORE_TYPE}","image":{{"docker-manifest-digest":"{DIGEST}"}},"identity":{{"docker-reference":"a/b:c"}}}},"optional":null}}"#
        );
        assert_eq!(
            parse_payload(null_optional.as_bytes(), SIGSTORE_TYPE)
                .unwrap()
                .docker_reference,
            "a/b:c"
        );
        // an integral timestamp written as a float is an integer
        let float_timestamp = null_optional.replace("null", r#"{"timestamp":1.7e9,"creator":"c"}"#);
        let parsed = parse_payload(float_timestamp.as_bytes(), SIGSTORE_TYPE).unwrap();
        assert_eq!(parsed.timestamp, 1_700_000_000);
        for bad in [
            r#"{"critical":{"type":"x","image":{},"identity":{}},"optional":[]}"#,
            r#"{"critical":{}}"#,
            r#"{"critical":{"type":"x","image":{},"identity":{}},"optional":{},"extra":1}"#,
            r#"{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"md5:00"},"identity":{"docker-reference":"a"}},"optional":{}}"#,
            r#"{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"sha256:00"},"identity":{"docker-reference":"a"},"x":1},"optional":{}}"#,
            r#"{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"identity":{"docker-reference":"a"}},"optional":{"timestamp":1.5}}"#,
            r#"{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"identity":{"docker-reference":"a"}},"optional":{"creator":1}}"#,
            "[]",
            "",
        ] {
            assert!(
                parse_payload(bad.as_bytes(), SIGSTORE_TYPE).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn manifests_match_their_digest() {
        let m = b"{\"schemaVersion\":2}";
        let d = format!("sha256:{}", hex::encode(openssl::sha::sha256(m)));
        assert!(manifest_matches(m, &d));
        assert!(!manifest_matches(b"{}", &d));
        let d512 = format!("sha512:{}", hex::encode(openssl::sha::sha512(m)));
        assert!(manifest_matches(m, &d512));
        assert!(!manifest_matches(m, "sha256:XYZ"));
    }

    #[test]
    fn blobs_round_trip() {
        let sig = signature(&ec_key(), &payload(SIGSTORE_TYPE, "a"), None);
        let s = Signature::Sigstore(sig);
        assert_eq!(Signature::from_blob(&s.to_blob()).unwrap(), s);
        let simple = Signature::Simple(vec![0xa3, 1, 2]);
        assert_eq!(Signature::from_blob(&simple.to_blob()).unwrap(), simple);
        assert_eq!(
            Signature::from_blob(b"\0simple-signing\n\xc2\x01").unwrap(),
            Signature::Simple(vec![0xc2, 1])
        );
        for bad in [
            &b""[..],
            b"\0nope\nx",
            b"\0sigstore-json",
            b"hello",
            b"\0sigstore-json\n{}",
        ] {
            assert!(Signature::from_blob(bad).is_err());
        }
    }

    #[test]
    fn signatures_by_public_keys_verify() {
        let key = ec_key();
        let other = ec_key();
        let p = payload(SIGSTORE_TYPE, "localhost/a:b");
        let root = TrustRoot {
            public_keys: vec![public(&other), public(&key)],
            ..Default::default()
        };
        let got = root.verify(&signature(&key, &p, None), 0).unwrap();
        assert_eq!(got.docker_reference, "localhost/a:b");
        // another key, another payload, another type, no signature
        let only_other = TrustRoot {
            public_keys: vec![public(&other)],
            ..Default::default()
        };
        assert!(only_other.verify(&signature(&key, &p, None), 0).is_err());
        let mut s = signature(&key, &p, None);
        s.payload[3] ^= 1;
        assert!(root.verify(&s, 0).is_err());
        assert!(root
            .verify(
                &signature(&key, &payload(SIMPLE_SIGNING_TYPE, "a"), None),
                0
            )
            .is_err());
        let mut s = signature(&key, &p, None);
        s.annotations.clear();
        assert!(root.verify(&s, 0).is_err());
    }

    #[test]
    fn rsa_and_ed25519_keys_verify() {
        let p = payload(SIGSTORE_TYPE, "a");
        let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let ed = PKey::generate_ed25519().unwrap();
        let ed_sig = {
            let mut s = openssl::sign::Signer::new_without_digest(&ed).unwrap();
            s.sign_oneshot_to_vec(&p).unwrap()
        };
        for (key, sig) in [(&rsa, sign(&rsa, &p)), (&ed, ed_sig)] {
            let root = TrustRoot {
                public_keys: vec![public_key_from_pem(&pem(key)).unwrap()],
                ..Default::default()
            };
            let mut annotations = BTreeMap::new();
            annotations.insert(SIGNATURE_ANNOTATION.to_string(), b64(&sig));
            let s = Sigstore {
                mime_type: SIGSTORE_MEDIA_TYPE.into(),
                payload: p.clone(),
                annotations,
            };
            root.verify(&s, 0).unwrap();
        }
    }

    #[test]
    fn keys_with_rekor_need_their_set() {
        let key = ec_key();
        let rekor = ec_key();
        let p = payload(SIGSTORE_TYPE, "a");
        let root = TrustRoot {
            public_keys: vec![public(&key)],
            rekor_keys: vec![public(&rekor)],
            ..Default::default()
        };
        root.verify(&signature(&key, &p, Some((&rekor, &pem(&key)))), 0)
            .unwrap();
        // no SET, a SET by another log, a SET of another key
        assert!(root.verify(&signature(&key, &p, None), 0).is_err());
        assert!(root
            .verify(&signature(&key, &p, Some((&ec_key(), &pem(&key)))), 0)
            .is_err());
        assert!(root
            .verify(&signature(&key, &p, Some((&rekor, &pem(&ec_key())))), 0)
            .is_err());
        // a SET whose payload was changed
        let mut s = signature(&key, &p, Some((&rekor, &pem(&key))));
        let set = s.annotations.get_mut(SET_ANNOTATION).unwrap();
        *set = set.replace("\"logIndex\":7", "\"logIndex\":8");
        assert!(root.verify(&s, 0).is_err());
    }

    #[test]
    fn canonical_json_is_rfc_8785() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":[1,"x\u0001\"\n"],"a":{"é":true,"z":null},"A":-3}"#)
                .unwrap();
        let mut out = String::new();
        canonical_json(&v, &mut out).unwrap();
        assert_eq!(
            out,
            r#"{"A":-3,"a":{"z":null,"é":true},"b":[1,"x\u0001\"\n"]}"#
        );
        assert!(canonical_json(&serde_json::json!(1.5), &mut String::new()).is_err());
    }

    fn name(cn: &str) -> openssl::x509::X509Name {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", cn).unwrap();
        n.build()
    }

    fn ca(key: &PKey<Private>) -> X509 {
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name("test CA")).unwrap();
        b.set_issuer_name(&name("test CA")).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(TIME - 86400).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(TIME + 86400 * 365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    /// A leaf certificate of `key` by the CA, valid for ten minutes from
    /// TIME, with `email`, and Fulcio's issuer extensions when `issuer` is
    /// given.
    pub fn leaf(
        ca_key: &PKey<Private>,
        ca: &X509,
        key: &PKey<Private>,
        email: &str,
        issuer: Option<&str>,
        code_signing: bool,
    ) -> X509 {
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name("signer")).unwrap();
        b.set_issuer_name(ca.subject_name()).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(TIME - 60).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(TIME + 600).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&b.x509v3_context(Some(ca), None))
            .unwrap();
        b.append_extension(san).unwrap();
        let mut eku = ExtendedKeyUsage::new();
        if code_signing {
            eku.code_signing();
        } else {
            eku.server_auth();
        }
        b.append_extension(eku.build().unwrap()).unwrap();
        if let Some(i) = issuer {
            let v1 = Asn1Object::from_str("1.3.6.1.4.1.57264.1.1").unwrap();
            let v2 = Asn1Object::from_str("1.3.6.1.4.1.57264.1.8").unwrap();
            let raw = Asn1OctetString::new_from_bytes(i.as_bytes()).unwrap();
            b.append_extension(X509Extension::new_from_der(&v1, false, &raw).unwrap())
                .unwrap();
            let mut utf8 = vec![0x0c, i.len() as u8];
            utf8.extend_from_slice(i.as_bytes());
            let der = Asn1OctetString::new_from_bytes(&utf8).unwrap();
            b.append_extension(X509Extension::new_from_der(&v2, false, &der).unwrap())
                .unwrap();
        }
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn fulcio_sig(
        key: &PKey<Private>,
        cert: &X509,
        rekor: &PKey<Private>,
        p: &[u8],
        time: i64,
    ) -> Sigstore {
        let cert_pem = cert.to_pem().unwrap();
        let sig = sign(key, p);
        let mut annotations = BTreeMap::new();
        annotations.insert(SIGNATURE_ANNOTATION.to_string(), b64(&sig));
        annotations.insert(
            CERTIFICATE_ANNOTATION.to_string(),
            String::from_utf8(cert_pem.clone()).unwrap(),
        );
        annotations.insert(
            SET_ANNOTATION.to_string(),
            rekor_set(rekor, &cert_pem, &sig, p, time),
        );
        Sigstore {
            mime_type: SIGSTORE_MEDIA_TYPE.into(),
            payload: p.to_vec(),
            annotations,
        }
    }

    #[test]
    fn fulcio_certificates_logged_in_rekor_verify() {
        let ca_key = ec_key();
        let ca_cert = ca(&ca_key);
        let rekor = ec_key();
        let key = ec_key();
        let p = payload(SIGSTORE_TYPE, "quay.io/a/b:1");
        let root = |issuer: &str, email: &str| TrustRoot {
            fulcio: Some(Fulcio {
                ca: vec![ca_cert.clone()],
                oidc_issuer: issuer.into(),
                subject_email: email.into(),
            }),
            rekor_keys: vec![public(&rekor)],
            ..Default::default()
        };
        let cert = leaf(
            &ca_key,
            &ca_cert,
            &key,
            "me@example.com",
            Some("https://issuer"),
            true,
        );
        let good = root("https://issuer", "me@example.com");
        good.verify(&fulcio_sig(&key, &cert, &rekor, &p, TIME), 0)
            .unwrap();
        // another issuer, another email
        assert!(root("https://other", "me@example.com")
            .verify(&fulcio_sig(&key, &cert, &rekor, &p, TIME), 0)
            .is_err());
        assert!(root("https://issuer", "you@example.com")
            .verify(&fulcio_sig(&key, &cert, &rekor, &p, TIME), 0)
            .is_err());
        // logged after the certificate expired
        let e = good
            .verify(&fulcio_sig(&key, &cert, &rekor, &p, TIME + 3600), 0)
            .unwrap_err();
        assert!(e.0.contains("leaf certificate"), "{e}");
        // a certificate of another CA, without the issuer, not for code
        // signing
        let other_ca = ec_key();
        let other_cert = leaf(
            &other_ca,
            &ca(&other_ca),
            &key,
            "me@example.com",
            Some("https://issuer"),
            true,
        );
        assert!(good
            .verify(&fulcio_sig(&key, &other_cert, &rekor, &p, TIME), 0)
            .is_err());
        let no_issuer = leaf(&ca_key, &ca_cert, &key, "me@example.com", None, true);
        assert!(good
            .verify(&fulcio_sig(&key, &no_issuer, &rekor, &p, TIME), 0)
            .is_err());
        let not_code = leaf(
            &ca_key,
            &ca_cert,
            &key,
            "me@example.com",
            Some("https://issuer"),
            false,
        );
        let e = good
            .verify(&fulcio_sig(&key, &not_code, &rekor, &p, TIME), 0)
            .unwrap_err();
        assert!(e.0.contains("code signing"), "{e}");
        // signed by another key than the certificate's
        assert!(good
            .verify(&fulcio_sig(&ec_key(), &cert, &rekor, &p, TIME), 0)
            .is_err());
        // Fulcio without Rekor is refused
        let mut no_rekor = root("https://issuer", "me@example.com");
        no_rekor.rekor_keys.clear();
        assert!(no_rekor
            .verify(&fulcio_sig(&key, &cert, &rekor, &p, TIME), 0)
            .is_err());
    }

    #[test]
    fn a_pki_hostname_is_not_taken_from_the_common_name() {
        // the leaf's subject is CN=signer, and it has no DNS name
        let ca_key = ec_key();
        let ca_cert = ca(&ca_key);
        let key = ec_key();
        let cert = leaf(&ca_key, &ca_cert, &key, "me@example.com", None, true);
        let root = TrustRoot {
            pki: Some(Pki {
                roots: vec![ca_cert.clone()],
                intermediates: Vec::new(),
                subject_email: None,
                subject_hostname: Some("signer".into()),
            }),
            ..Default::default()
        };
        let mut s = signature(&key, &payload(SIGSTORE_TYPE, "a"), None);
        s.annotations.insert(
            CERTIFICATE_ANNOTATION.to_string(),
            String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        );
        assert!(root.verify(&s, TIME).is_err());
    }

    #[test]
    fn pki_certificates_verify_now() {
        let ca_key = ec_key();
        let ca_cert = ca(&ca_key);
        let key = ec_key();
        let cert = leaf(&ca_key, &ca_cert, &key, "me@example.com", None, true);
        let p = payload(SIGSTORE_TYPE, "a");
        let root = TrustRoot {
            pki: Some(Pki {
                roots: vec![ca_cert.clone()],
                intermediates: Vec::new(),
                subject_email: Some("me@example.com".into()),
                subject_hostname: None,
            }),
            ..Default::default()
        };
        let mut s = signature(&key, &p, None);
        s.annotations.insert(
            CERTIFICATE_ANNOTATION.to_string(),
            String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        );
        root.verify(&s, TIME).unwrap();
        assert!(root.verify(&s, TIME + 86400).is_err(), "expired");
    }

    #[test]
    fn the_fulcio_issuer_is_read_from_der() {
        let ca_key = ec_key();
        let ca_cert = ca(&ca_key);
        let cert = leaf(&ca_key, &ca_cert, &ec_key(), "a@b", Some("https://x"), true);
        assert_eq!(fulcio_issuer(&cert.to_der().unwrap()).unwrap(), "https://x");
        let der = cert.to_der().unwrap();
        for n in 0..der.len() {
            let _ = extensions(&der[..n]);
        }
    }
}
