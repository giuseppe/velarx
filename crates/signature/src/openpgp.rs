// SPDX-License-Identifier: Apache-2.0
//! OpenPGP as the simple signing of containers/image needs it: the
//! public keys of a keyring (`signedBy` with `GPGKeys`), and the signed
//! messages of the signatures, whose content is given only when one of
//! the keys made the signature.
//!
//! The packets are parsed here (RFC 4880 and the v4 parts of RFC 9580);
//! the cryptography is OpenSSL's.  What is not needed is refused rather
//! than half supported: version 3, 5 and 6 signatures and keys, text
//! signatures, SHA-1 and MD5, BZip2.  Everything parsed comes from an
//! untrusted signature or from a keyring of the configuration: every
//! length is checked, every size bounded.

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::sign::Verifier;
use std::io::Read;
use velarx_sigparse_core as sigparse;

/// Largest signed content (the JSON of a simple signing signature is
/// a few hundred bytes), and what all the compressed packets of a message
/// may inflate to together.
const MAX_CONTENT: u64 = 4 << 20;
/// Largest compressed or literal data accepted, and nesting of compressed
/// packets.
const MAX_DEPTH: usize = 2;

const TAG_SIGNATURE: u8 = 2;
const TAG_ONE_PASS: u8 = 4;
const TAG_SECRET_KEY: u8 = 5;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_SECRET_SUBKEY: u8 = 7;
const TAG_COMPRESSED: u8 = 8;
const TAG_MARKER: u8 = 10;
const TAG_LITERAL: u8 = 11;
const TAG_USER_ID: u8 = 13;
const TAG_PUBLIC_SUBKEY: u8 = 14;
const TAG_USER_ATTRIBUTE: u8 = 17;
/// Packets of a signed message at most (a compressed packet, a one-pass
/// signature, the literal data and the signature, a few of each).
const MAX_MESSAGE_PACKETS: usize = 64;

const ALGO_RSA: u8 = 1;
const ALGO_RSA_SIGN: u8 = 3;
const ALGO_DSA: u8 = 17;
const ALGO_ECDSA: u8 = 19;
const ALGO_EDDSA_LEGACY: u8 = 22;
const ALGO_ED25519: u8 = 27;

const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

/// Why a keyring or a signature is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<sigparse::Error> for Error {
    fn from(e: sigparse::Error) -> Self {
        use sigparse::Error as E;
        Error(match e {
            E::Truncated => "truncated OpenPGP data".into(),
            E::NotAPacket => "not an OpenPGP packet".into(),
            E::TooManyPackets => "too many OpenPGP packets".into(),
            E::PartialLength => "a partial length for a packet that cannot have one".into(),
            E::Version(v) => format!("version {v} signatures are not supported"),
            E::EmptySubpacket => "an empty signature subpacket".into(),
            E::BadTime => "an invalid time subpacket".into(),
            E::UnknownCritical(k) => format!("an unknown critical signature subpacket {k}"),
            E::Algorithm(n) => format!("unsupported signature algorithm {n}"),
        })
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// Bytes read in order, every read checked.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.data.len() {
            return err("truncated OpenPGP data");
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A multiprecision integer: its bytes, without the bit count.
    fn mpi(&mut self) -> Result<&'a [u8], Error> {
        let bits = usize::from(self.u16()?);
        let v = self.take(bits.div_ceil(8))?;
        // a leading zero byte would not be counted
        Ok(v)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }
}

/// A packet: its tag and its body (partial lengths joined).
struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// The packets of `data`, in order (partial lengths joined).
fn packets(data: &[u8]) -> Result<Vec<Packet>, Error> {
    let mut out = Vec::new();
    for p in sigparse::packets(data)? {
        let mut body = p.body.of(data).to_vec();
        for piece in &p.more {
            body.extend_from_slice(piece.of(data));
        }
        out.push(Packet { tag: p.tag, body });
    }
    Ok(out)
}

/// A hash algorithm of signatures.
fn digest_of(algo: u8) -> Result<MessageDigest, Error> {
    match algo {
        8 => Ok(MessageDigest::sha256()),
        9 => Ok(MessageDigest::sha384()),
        10 => Ok(MessageDigest::sha512()),
        11 => Ok(MessageDigest::sha224()),
        1 | 2 => err("signatures with MD5 or SHA-1 are not accepted"),
        n => err(format!("unsupported hash algorithm {n}")),
    }
}

/// A public key of a keyring, usable to verify signatures.
#[derive(Clone)]
pub struct Key {
    /// The v4 fingerprint, upper case hex, as containers/image names keys.
    pub fingerprint: String,
    /// The fingerprint of the primary key it belongs to.
    pub primary: String,
    key_id: [u8; 8],
    algo: u8,
    pkey: PKey<Public>,
    /// RSA: the size of the modulus in bytes (signatures are padded to it).
    rsa_len: usize,
    created: u32,
    /// Seconds since `created` after which it is expired.
    expires: Option<u32>,
    revoked: bool,
    can_sign: bool,
    /// For a subkey: when its primary key expires (seconds since the
    /// epoch), and whether it is revoked.
    primary_expires_at: Option<u64>,
    primary_revoked: bool,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &self.fingerprint)
            .field("primary", &self.primary)
            .finish()
    }
}

fn ec_point_key(curve: Nid, point: &[u8]) -> Result<PKey<Public>, Error> {
    let group = EcGroup::from_curve_name(curve).map_err(|e| Error(e.to_string()))?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| Error(e.to_string()))?;
    let point = EcPoint::from_bytes(&group, point, &mut ctx)
        .map_err(|_| Error("invalid ECDSA public key".into()))?;
    let key = EcKey::from_public_key(&group, &point).map_err(|e| Error(e.to_string()))?;
    key.check_key()
        .map_err(|_| Error("invalid ECDSA public key".into()))?;
    PKey::from_ec_key(key).map_err(|e| Error(e.to_string()))
}

fn bn(b: &[u8]) -> Result<BigNum, Error> {
    BigNum::from_slice(b).map_err(|e| Error(e.to_string()))
}

/// A public key: the key, its algorithm, the size of an RSA modulus, its
/// creation time.
type PublicKeyFields = (PKey<Public>, u8, usize, u32);

/// The key of a public key packet body (v4 only); None for an algorithm
/// that cannot sign or that is not supported.
fn parse_public_key(body: &[u8]) -> Result<Option<PublicKeyFields>, Error> {
    let mut c = Cursor::new(body);
    let version = c.u8()?;
    if version != 4 {
        return Ok(None);
    }
    let created = c.u32()?;
    let algo = c.u8()?;
    let (pkey, rsa_len) = match algo {
        ALGO_RSA | ALGO_RSA_SIGN => {
            let n = c.mpi()?;
            let e = c.mpi()?;
            let rsa = openssl::rsa::Rsa::from_public_components(bn(n)?, bn(e)?)
                .map_err(|e| Error(e.to_string()))?;
            // weak keys are left out of the keyring
            if rsa.size() < 256 {
                return Ok(None);
            }
            let len = rsa.size() as usize;
            (PKey::from_rsa(rsa).map_err(|e| Error(e.to_string()))?, len)
        }
        ALGO_DSA => {
            let (p, q, g, y) = (c.mpi()?, c.mpi()?, c.mpi()?, c.mpi()?);
            if bn(p)?.num_bits() < 2048 {
                return Ok(None);
            }
            let dsa = openssl::dsa::Dsa::from_public_components(bn(p)?, bn(q)?, bn(g)?, bn(y)?)
                .map_err(|e| Error(e.to_string()))?;
            (PKey::from_dsa(dsa).map_err(|e| Error(e.to_string()))?, 0)
        }
        ALGO_ECDSA => {
            let n = usize::from(c.u8()?);
            let oid = c.take(n)?;
            let curve = match oid {
                OID_P256 => Nid::X9_62_PRIME256V1,
                OID_P384 => Nid::SECP384R1,
                OID_P521 => Nid::SECP521R1,
                _ => return Ok(None),
            };
            (ec_point_key(curve, c.mpi()?)?, 0)
        }
        ALGO_EDDSA_LEGACY => {
            let n = usize::from(c.u8()?);
            if c.take(n)? != OID_ED25519 {
                return Ok(None);
            }
            let point = c.mpi()?;
            let raw = match point {
                [0x40, raw @ ..] if raw.len() == 32 => raw,
                _ => return err("invalid Ed25519 public key"),
            };
            (
                PKey::public_key_from_raw_bytes(raw, Id::ED25519)
                    .map_err(|e| Error(e.to_string()))?,
                0,
            )
        }
        ALGO_ED25519 => {
            let raw = c.take(32)?;
            (
                PKey::public_key_from_raw_bytes(raw, Id::ED25519)
                    .map_err(|e| Error(e.to_string()))?,
                0,
            )
        }
        _ => return Ok(None),
    };
    Ok(Some((pkey, algo, rsa_len, created)))
}

/// The v4 fingerprint of a public key packet body.
fn fingerprint(body: &[u8]) -> Result<[u8; 20], Error> {
    let len = u16::try_from(body.len()).map_err(|_| Error("public key too long".into()))?;
    let mut h =
        openssl::hash::Hasher::new(MessageDigest::sha1()).map_err(|e| Error(e.to_string()))?;
    let mut feed = |b: &[u8]| h.update(b).map_err(|e| Error(e.to_string()));
    feed(&[0x99])?;
    feed(&len.to_be_bytes())?;
    feed(body)?;
    let d = h.finish().map_err(|e| Error(e.to_string()))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&d);
    Ok(out)
}

/// What the subpackets of a signature say.
struct Subpackets {
    created: Option<u32>,
    expires: Option<u32>,
    key_expires: Option<u32>,
    key_flags: Option<u8>,
    issuer: Option<[u8; 8]>,
    issuer_fpr: Option<Vec<u8>>,
    /// Embedded signatures (the back-signatures of signing subkeys).
    embedded: Vec<Vec<u8>>,
}

/// A v4 signature packet.
struct Signature {
    sig_type: u8,
    algo: u8,
    hash: u8,
    /// The bytes hashed after the data: version to hashed subpackets,
    /// then the trailer.
    trailer: Vec<u8>,
    left16: [u8; 2],
    /// The signature, as OpenSSL verifies it.
    mpis: Vec<Vec<u8>>,
    sub: Subpackets,
}

fn parse_signature(body: &[u8]) -> Result<Signature, Error> {
    let f = sigparse::signature(body)?;
    let bytes = |s: &sigparse::Span| s.of(body).to_vec();
    let hashed_part = &body[..f.hashed.end()];
    let mut trailer = hashed_part.to_vec();
    trailer.extend_from_slice(&[0x04, 0xff]);
    trailer.extend_from_slice(&(hashed_part.len() as u32).to_be_bytes());
    Ok(Signature {
        sig_type: f.sig_type,
        algo: f.algo,
        hash: f.hash,
        trailer,
        left16: f.left16,
        mpis: f.values.iter().map(bytes).collect(),
        sub: Subpackets {
            created: f.sub.created,
            expires: f.sub.expires,
            key_expires: f.sub.key_expires,
            key_flags: f.sub.key_flags,
            issuer: f.sub.issuer,
            issuer_fpr: f.sub.issuer_fpr.as_ref().map(bytes),
            embedded: f.sub.embedded.iter().map(bytes).collect(),
        },
    })
}

/// A big-endian integer left padded to `n` bytes (MPIs lose their leading
/// zeros).
fn pad(v: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    let v = &v[v.iter().take_while(|b| **b == 0).count()..];
    if v.len() > n {
        return err("a signature value too large for its key");
    }
    let mut out = vec![0u8; n - v.len()];
    out.extend_from_slice(v);
    Ok(out)
}

fn der_sig(r: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
    let sig = openssl::ecdsa::EcdsaSig::from_private_components(bn(r)?, bn(s)?)
        .map_err(|e| Error(e.to_string()))?;
    sig.to_der().map_err(|e| Error(e.to_string()))
}

impl Key {
    /// Whether `sig` over `data` was made by this key.
    fn verifies(&self, sig: &Signature, data: &[u8]) -> Result<bool, Error> {
        if sig.algo != self.algo
            && !(matches!(sig.algo, ALGO_RSA | ALGO_RSA_SIGN)
                && matches!(self.algo, ALGO_RSA | ALGO_RSA_SIGN))
        {
            return Ok(false);
        }
        let md = digest_of(sig.hash)?;
        // the digest of the data and the trailer
        let mut h = openssl::hash::Hasher::new(md).map_err(|e| Error(e.to_string()))?;
        h.update(data).map_err(|e| Error(e.to_string()))?;
        h.update(&sig.trailer).map_err(|e| Error(e.to_string()))?;
        let digest = h.finish().map_err(|e| Error(e.to_string()))?;
        if digest.get(..2) != Some(&sig.left16[..]) {
            return Ok(false);
        }
        let ok = match self.algo {
            ALGO_RSA | ALGO_RSA_SIGN => {
                let s = pad(&sig.mpis[0], self.rsa_len)?;
                let mut v = Verifier::new(md, &self.pkey).map_err(|e| Error(e.to_string()))?;
                v.update(data).map_err(|e| Error(e.to_string()))?;
                v.update(&sig.trailer).map_err(|e| Error(e.to_string()))?;
                v.verify(&s).unwrap_or(false)
            }
            ALGO_DSA | ALGO_ECDSA => {
                let der = der_sig(&sig.mpis[0], &sig.mpis[1])?;
                let mut v = Verifier::new(md, &self.pkey).map_err(|e| Error(e.to_string()))?;
                v.update(data).map_err(|e| Error(e.to_string()))?;
                v.update(&sig.trailer).map_err(|e| Error(e.to_string()))?;
                v.verify(&der).unwrap_or(false)
            }
            // EdDSA signs the digest itself
            ALGO_EDDSA_LEGACY | ALGO_ED25519 => {
                let raw = if self.algo == ALGO_ED25519 {
                    sig.mpis[0].clone()
                } else {
                    let mut r = pad(&sig.mpis[0], 32)?;
                    r.extend(pad(&sig.mpis[1], 32)?);
                    r
                };
                let mut v =
                    Verifier::new_without_digest(&self.pkey).map_err(|e| Error(e.to_string()))?;
                v.verify_oneshot(&raw, &digest).unwrap_or(false)
            }
            _ => false,
        };
        Ok(ok)
    }

    /// Why this key cannot make a signature valid at `now`, if it cannot.
    fn unusable(&self, now: u64) -> Option<String> {
        if self.revoked {
            return Some(format!("the key {} is revoked", self.fingerprint));
        }
        if !self.can_sign {
            return Some(format!("the key {} is not for signing", self.fingerprint));
        }
        if let Some(e) = self.expires.filter(|e| *e != 0) {
            if u64::from(self.created) + u64::from(e) <= now {
                return Some(format!("the key {} is expired", self.fingerprint));
            }
        }
        if self.primary_revoked {
            return Some(format!("the primary key {} is revoked", self.primary));
        }
        if self.primary_expires_at.is_some_and(|t| t <= now) {
            return Some(format!("the primary key {} is expired", self.primary));
        }
        None
    }
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02X}")).collect()
}

/// The keys of a keyring: binary packets or ASCII armor, several blocks
/// and several keys each.  Keys that cannot sign, of other versions or
/// algorithms are left out.
pub fn parse_keyring(data: &[u8]) -> Result<Vec<Key>, Error> {
    let binary = if data.first().is_some_and(|b| b & 0x80 != 0) {
        vec![data.to_vec()]
    } else {
        dearmor_all(data)?
    };
    let mut keys = Vec::new();
    for block in binary {
        parse_keys(&block, &mut keys)?;
    }
    Ok(keys)
}

/// A primary key and what follows it in a keyring.
#[derive(Default)]
struct Block {
    primary: Vec<u8>,
    /// Signatures right after the key (direct key signatures, revocations).
    direct: Vec<Vec<u8>>,
    /// User IDs and attributes: tag, body, their signatures.
    ids: Vec<(u8, Vec<u8>, Vec<Vec<u8>>)>,
    /// Subkeys: body, their signatures.
    subkeys: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

/// The type of a signature packet, also of one that does not parse: None
/// when even that cannot be read.
fn signature_type(body: &[u8]) -> Option<u8> {
    match body.first()? {
        3 => body.get(2).copied(),
        _ => body.get(1).copied(),
    }
}

/// A key packet as the signatures over it hash it.
fn framed_key(body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(body.len()).map_err(|_| Error("a key packet too long".into()))?;
    let mut out = vec![0x99];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A user ID (0xB4) or attribute (0xD1) as certifications hash it.
fn framed_id(tag: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u32::try_from(body.len()).map_err(|_| Error("a user ID too long".into()))?;
    let mut out = vec![if tag == TAG_USER_ID { 0xb4 } else { 0xd1 }];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// The blocks of the packets of a keyring.
fn blocks(data: &[u8]) -> Result<Vec<Block>, Error> {
    let mut out: Vec<Block> = Vec::new();
    for p in packets(data)? {
        match p.tag {
            TAG_SECRET_KEY | TAG_SECRET_SUBKEY => return err("the keyring has secret keys"),
            TAG_PUBLIC_KEY => out.push(Block {
                primary: p.body,
                ..Block::default()
            }),
            _ => {
                let Some(b) = out.last_mut() else { continue };
                match p.tag {
                    TAG_USER_ID | TAG_USER_ATTRIBUTE => b.ids.push((p.tag, p.body, Vec::new())),
                    TAG_PUBLIC_SUBKEY => b.subkeys.push((p.body, Vec::new())),
                    TAG_SIGNATURE => {
                        if signature_type(&p.body).is_none() {
                            return err("a signature packet of the keyring that cannot be read");
                        }
                        if let Some((_, sigs)) = b.subkeys.last_mut() {
                            sigs.push(p.body);
                        } else if let Some((_, _, sigs)) = b.ids.last_mut() {
                            sigs.push(p.body);
                        } else {
                            b.direct.push(p.body);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

/// A key as its packet says, without what signatures say yet.
fn new_key(body: &[u8], primary: Option<&str>) -> Result<Option<Key>, Error> {
    let Some((pkey, algo, rsa_len, created)) = parse_public_key(body)? else {
        return Ok(None);
    };
    let fpr = fingerprint(body)?;
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&fpr[12..]);
    let fingerprint = hex_upper(&fpr);
    Ok(Some(Key {
        primary: primary.map_or_else(|| fingerprint.clone(), String::from),
        fingerprint,
        key_id,
        algo,
        pkey,
        rsa_len,
        created,
        expires: None,
        revoked: false,
        can_sign: false,
        primary_expires_at: None,
        primary_revoked: false,
    }))
}

/// Whether `raw` is a signature of type `types` by `by` over `data`; any
/// failure (an unsupported hash, a bad signature) is a no.
fn verified(by: &Key, raw: &[u8], types: &[u8], data: &[u8]) -> Option<Signature> {
    let sig = parse_signature(raw).ok()?;
    if !types.contains(&sig.sig_type) || sig.sub.created.is_none() {
        return None;
    }
    by.verifies(&sig, data).ok()?.then_some(sig)
}

/// The keys of a keyring's binary packets.  Every self-signature, binding
/// and back-signature is verified, and only what they say counts: a key
/// without a valid self-signature cannot sign, a subkey without a valid
/// binding (and back-signature, for signing) is left out.  A revocation
/// revokes, even one that does not parse or verify (the keyring is the
/// configuration: failing closed is what it would want).  A self-signature
/// that cannot be read (an unknown critical subpacket, say) is skipped and
/// an older one supplies the expiry and the flags, where go-crypto refuses
/// the key.  That is the safer side: the older signature only says what the
/// owner had said before, and the key is not used for more than that, while
/// a revocation that cannot be read still revokes.
fn parse_keys(data: &[u8], keys: &mut Vec<Key>) -> Result<(), Error> {
    for block in blocks(data)? {
        let Some(mut primary) = new_key(&block.primary, None)? else {
            continue;
        };
        let primary_framed = framed_key(&block.primary)?;
        let all_sigs = || {
            block
                .direct
                .iter()
                .chain(block.ids.iter().flat_map(|(_, _, s)| s.iter()))
        };
        primary.revoked = all_sigs().any(|raw| signature_type(raw) == Some(0x20));
        // the newest valid self-signature says the expiry and the flags
        let mut newest: Option<Signature> = None;
        let mut keep = |sig: Signature| {
            if newest
                .as_ref()
                .is_none_or(|n| sig.sub.created >= n.sub.created)
            {
                newest = Some(sig);
            }
        };
        for raw in &block.direct {
            if let Some(sig) = verified(&primary, raw, &[0x1f], &primary_framed) {
                keep(sig);
            }
        }
        for (tag, body, sigs) in &block.ids {
            let mut data = primary_framed.clone();
            data.extend(framed_id(*tag, body)?);
            for raw in sigs {
                if let Some(sig) = verified(&primary, raw, &[0x10, 0x11, 0x12, 0x13], &data) {
                    keep(sig);
                }
            }
        }
        if let Some(sig) = &newest {
            primary.expires = sig.sub.key_expires;
            primary.can_sign = sig.sub.key_flags.is_none_or(|f| f & 0x02 != 0);
        }
        let primary_expires_at = primary
            .expires
            .filter(|e| *e != 0)
            .map(|e| u64::from(primary.created) + u64::from(e));
        let has_self_sig = newest.is_some();
        let mut subkeys = Vec::new();
        for (body, sigs) in &block.subkeys {
            let Some(mut sub) = new_key(body, Some(&primary.fingerprint))? else {
                continue;
            };
            let mut data = primary_framed.clone();
            data.extend(framed_key(body)?);
            sub.revoked = sigs.iter().any(|raw| signature_type(raw) == Some(0x28));
            sub.primary_revoked = primary.revoked;
            sub.primary_expires_at = primary_expires_at;
            let mut binding: Option<Signature> = None;
            for raw in sigs {
                if let Some(sig) = verified(&primary, raw, &[0x18], &data) {
                    if binding
                        .as_ref()
                        .is_none_or(|b| sig.sub.created >= b.sub.created)
                    {
                        binding = Some(sig);
                    }
                }
            }
            let Some(binding) = binding.filter(|_| has_self_sig) else {
                continue;
            };
            sub.expires = binding.sub.key_expires;
            // a subkey signs when its binding says so and it signed the
            // binding back
            let signs = binding.sub.key_flags.is_some_and(|f| f & 0x02 != 0);
            sub.can_sign = signs
                && binding
                    .sub
                    .embedded
                    .iter()
                    .any(|raw| verified(&sub, raw, &[0x19], &data).is_some());
            subkeys.push(sub);
        }
        if !has_self_sig {
            primary.can_sign = false;
        }
        keys.push(primary);
        keys.extend(subkeys);
    }
    Ok(())
}

/// The binary blocks of ASCII armor.
fn dearmor_all(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    use base64::Engine;
    let text = std::str::from_utf8(data)
        .map_err(|_| Error("the keyring is neither binary nor ASCII armor".into()))?;
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim_end);
    while let Some(line) = lines.next() {
        if !(line.starts_with("-----BEGIN PGP ") && line.ends_with("-----")) {
            continue;
        }
        // headers, up to a blank line
        for h in lines.by_ref() {
            if h.trim().is_empty() {
                break;
            }
        }
        let mut b64 = String::new();
        let mut ended = false;
        for l in lines.by_ref() {
            if l.starts_with("-----END PGP ") {
                ended = true;
                break;
            }
            // the checksum line
            if l.starts_with('=') {
                continue;
            }
            b64.push_str(l.trim());
        }
        if !ended {
            return err("ASCII armor without its end line");
        }
        out.push(
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| Error("invalid base64 in ASCII armor".into()))?,
        );
    }
    if out.is_empty() {
        return err("no OpenPGP data");
    }
    Ok(out)
}

/// The content of the literal data packet of a message, the signatures
/// over it.  `budget`: the bytes the message may still inflate to, all
/// its compressed packets together.
fn message_parts(
    data: &[u8],
    depth: usize,
    budget: &mut u64,
    content: &mut Option<Vec<u8>>,
    sigs: &mut Vec<Signature>,
) -> Result<(), Error> {
    let packets = packets(data)?;
    if packets.len() > MAX_MESSAGE_PACKETS {
        return err("a signed message with too many packets");
    }
    let mut compressed = false;
    for p in packets {
        match p.tag {
            TAG_COMPRESSED => {
                if depth >= MAX_DEPTH {
                    return err("compressed data nested too deep");
                }
                if compressed {
                    return err("a signed message with two compressed packets");
                }
                compressed = true;
                let (&algo, rest) = p
                    .body
                    .split_first()
                    .ok_or_else(|| Error("empty compressed data".into()))?;
                let mut inner = Vec::new();
                let read = match algo {
                    0 => {
                        inner.extend_from_slice(rest);
                        Ok(rest.len())
                    }
                    1 => flate2::read::DeflateDecoder::new(rest)
                        .take(*budget + 1)
                        .read_to_end(&mut inner),
                    2 => flate2::read::ZlibDecoder::new(rest)
                        .take(*budget + 1)
                        .read_to_end(&mut inner),
                    n => return err(format!("unsupported compression algorithm {n}")),
                };
                read.map_err(|_| Error("invalid compressed data".into()))?;
                if inner.len() as u64 > *budget {
                    return err("the signed message inflates too much");
                }
                *budget -= inner.len() as u64;
                message_parts(&inner, depth + 1, budget, content, sigs)?;
            }
            TAG_LITERAL => {
                if content.is_some() {
                    return err("a message with two literal data packets");
                }
                let mut c = Cursor::new(&p.body);
                let _format = c.u8()?;
                let name_len = usize::from(c.u8()?);
                c.take(name_len)?;
                c.u32()?;
                let data = c.rest();
                if data.len() as u64 > MAX_CONTENT {
                    return err("the signed content is too large");
                }
                *content = Some(data.to_vec());
            }
            TAG_SIGNATURE => sigs.push(parse_signature(&p.body)?),
            TAG_ONE_PASS => {}
            // a marker is only allowed first, outside of compression
            TAG_MARKER if depth == 0 => {}
            n => return err(format!("unexpected OpenPGP packet {n} in a signed message")),
        }
    }
    Ok(())
}

/// The content of the signed message `message` and the key of `keys` that
/// signed it, at `now` (seconds since the epoch); an error when no key of
/// `keys` made a valid signature of it.
pub fn verify_message(keys: &[Key], message: &[u8], now: u64) -> Result<(Vec<u8>, Key), Error> {
    let mut content = None;
    let mut sigs = Vec::new();
    let mut budget = MAX_CONTENT;
    message_parts(message, 0, &mut budget, &mut content, &mut sigs)?;
    let Some(content) = content else {
        return err("the signature has no signed content");
    };
    if sigs.is_empty() {
        return err("the message is not signed");
    }
    let mut why = Vec::new();
    for sig in &sigs {
        if sig.sig_type != 0x00 {
            why.push(format!(
                "a signature of type {:#04x} is not of binary data",
                sig.sig_type
            ));
            continue;
        }
        let Some(created) = sig.sub.created else {
            why.push("a signature without its creation time".to_string());
            continue;
        };
        if let Some(e) = sig.sub.expires.filter(|e| *e != 0) {
            if u64::from(created) + u64::from(e) <= now {
                why.push("the signature is expired".to_string());
                continue;
            }
        }
        // the keys it names first, then the others
        let named = |k: &Key| {
            sig.sub.issuer.is_some_and(|id| id == k.key_id)
                || sig
                    .sub
                    .issuer_fpr
                    .as_deref()
                    .is_some_and(|f| hex_upper(f) == k.fingerprint)
        };
        let mut candidates: Vec<&Key> = keys.iter().filter(|k| named(k)).collect();
        candidates.extend(keys.iter().filter(|k| !named(k)));
        for key in candidates {
            if !key.verifies(sig, &content)? {
                continue;
            }
            if let Some(reason) = key.unusable(now) {
                why.push(reason);
                continue;
            }
            if created < key.created {
                why.push(format!(
                    "the signature is older than the key {}",
                    key.fingerprint
                ));
                continue;
            }
            return Ok((content, key.clone()));
        }
        if !why
            .iter()
            .any(|w| w.starts_with("the key") || w.starts_with("the signature is older"))
        {
            let issuer = sig
                .sub
                .issuer_fpr
                .as_deref()
                .map(hex_upper)
                .or(sig.sub.issuer.map(|i| hex_upper(&i)))
                .unwrap_or_else(|| "an unknown key".into());
            why.push(format!("no trusted key verifies the signature by {issuer}"));
        }
    }
    err(why.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigparse::MAX_PACKETS;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signature/",
                $name
            ))
        };
    }

    /// When the fixtures were made (gpg, 2026-10-11).
    const NOW: u64 = 1_791_739_600;
    const PAYLOAD: &[u8] = fixture!("payload.json");

    fn keys(data: &[u8]) -> Vec<Key> {
        parse_keyring(data).unwrap()
    }

    #[test]
    fn signatures_of_every_algorithm_verify() {
        for (key, msg) in [
            (&fixture!("key-rsa.gpg")[..], &fixture!("msg-rsa.sig")[..]),
            (fixture!("key-rsa.asc"), fixture!("msg-rsa.sig")),
            (fixture!("key-ed.gpg"), fixture!("msg-ed.sig")),
            (fixture!("key-ec.gpg"), fixture!("msg-ec.sig")),
        ] {
            let k = keys(key);
            let (content, by) = verify_message(&k, msg, NOW).unwrap();
            assert_eq!(content, PAYLOAD);
            assert_eq!(by.primary, k[0].fingerprint);
        }
    }

    #[test]
    fn a_signing_subkey_verifies_for_its_primary() {
        let k = keys(fixture!("key-sub.gpg"));
        assert_eq!(k.len(), 2);
        assert!(!k[0].can_sign, "the primary only certifies");
        let (content, by) = verify_message(&k, fixture!("msg-sub.sig"), NOW).unwrap();
        assert_eq!(content, PAYLOAD);
        assert_eq!(by.fingerprint, k[1].fingerprint);
        assert_eq!(by.primary, k[0].fingerprint);
    }

    #[test]
    fn other_keys_do_not_verify() {
        let mut all = keys(fixture!("key-ed.gpg"));
        all.extend(keys(fixture!("key-ec.gpg")));
        let e = verify_message(&all, fixture!("msg-rsa.sig"), NOW).unwrap_err();
        assert!(e.0.contains("no trusted key"), "{e}");
        assert!(verify_message(&[], fixture!("msg-rsa.sig"), NOW).is_err());
    }

    #[test]
    fn revoked_and_expired_keys_do_not_verify() {
        let e = verify_message(
            &keys(fixture!("key-ec-revoked.gpg")),
            fixture!("msg-ec2.sig"),
            NOW,
        )
        .unwrap_err();
        assert!(e.0.contains("revoked"), "{e}");
        let old = keys(fixture!("key-old.gpg"));
        verify_message(&old, fixture!("msg-old.sig"), NOW).unwrap();
        let e = verify_message(&old, fixture!("msg-old.sig"), NOW + 2 * 86400).unwrap_err();
        assert!(e.0.contains("expired"), "{e}");
    }

    #[test]
    fn what_simple_signing_does_not_use_is_refused() {
        let k = keys(fixture!("key-rsa.gpg"));
        // text mode, a cleartext signature, SHA-1
        assert!(verify_message(&k, fixture!("msg-text.sig"), NOW).is_err());
        assert!(verify_message(&k, fixture!("msg-clear.asc"), NOW).is_err());
        let e = verify_message(&k, fixture!("msg-sha1.sig"), NOW).unwrap_err();
        assert!(e.0.contains("SHA-1"), "{e}");
    }

    #[test]
    fn changed_signatures_and_contents_do_not_verify() {
        let k = keys(fixture!("key-ed.gpg"));
        let msg = fixture!("msg-ed.sig");
        // the payload is stored as is (no compression): change a byte of it
        let at = msg.windows(8).position(|w| w == b"critical").unwrap();
        for i in [at, msg.len() - 1, msg.len() - 40] {
            let mut m = msg.to_vec();
            m[i] ^= 1;
            assert!(verify_message(&k, &m, NOW).is_err(), "byte {i}");
        }
        // every truncation fails cleanly
        for n in 0..msg.len() {
            assert!(verify_message(&k, &msg[..n], NOW).is_err());
        }
    }

    /// A new format packet with a four octet length.
    fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xc0 | tag, 255];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        let mut body = vec![2];
        body.extend(e.finish().unwrap());
        packet(TAG_COMPRESSED, &body)
    }

    fn literal(data: &[u8]) -> Vec<u8> {
        let mut body = vec![b'b', 0, 0, 0, 0, 0];
        body.extend_from_slice(data);
        packet(TAG_LITERAL, &body)
    }

    #[test]
    fn compression_bombs_are_refused_quickly() {
        let k = keys(fixture!("key-rsa.gpg"));
        let started = std::time::Instant::now();
        // one packet inflating past the budget
        let big = zlib(&zlib(&literal(&vec![0u8; 5 << 20])));
        let e = verify_message(&k, &big, NOW).unwrap_err();
        assert!(e.0.contains("inflates too much"), "{e}");
        // many packets that each fit, together over the budget: the second
        // compressed packet of a level is refused before it inflates
        let one = zlib(&literal(&vec![0u8; 3 << 20]));
        let many: Vec<u8> = std::iter::repeat_n(one.clone(), 1000).flatten().collect();
        let e = verify_message(&k, &zlib(&many), NOW).unwrap_err();
        assert!(
            e.0.contains("too many packets") || e.0.contains("two compressed"),
            "{e}"
        );
        let two: Vec<u8> = std::iter::repeat_n(one, 2).flatten().collect();
        let e = verify_message(&k, &zlib(&two), NOW).unwrap_err();
        assert!(e.0.contains("two compressed"), "{e}");
        // a marker inside compressed data
        let mut inner = packet(TAG_MARKER, b"PGP");
        inner.extend(literal(b"x"));
        let e = verify_message(&k, &zlib(&inner), NOW).unwrap_err();
        assert!(e.0.contains("unexpected OpenPGP packet 10"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// A v4 signature of type `sig_type` by `algo` that is no signature:
    /// creation time now, key flags `flags`, the issuer `issuer` in the
    /// unhashed part, made up values.
    fn forged(
        sig_type: u8,
        algo: u8,
        flags: Option<u8>,
        key_expires: Option<u32>,
        issuer: &str,
    ) -> Vec<u8> {
        let mut hashed = vec![5, 2];
        hashed.extend_from_slice(&(NOW as u32 + 10).to_be_bytes());
        if let Some(f) = flags {
            hashed.extend_from_slice(&[2, 27, f]);
        }
        if let Some(e) = key_expires {
            hashed.extend_from_slice(&[5, 9]);
            hashed.extend_from_slice(&e.to_be_bytes());
        }
        let fpr = hex::decode(issuer).unwrap();
        let mut unhashed = vec![(fpr.len() + 2) as u8, 33, 4];
        unhashed.extend_from_slice(&fpr);
        let mut body = vec![4, sig_type, algo, 8];
        body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        body.extend(hashed);
        body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
        body.extend(unhashed);
        body.extend_from_slice(&[0xab, 0xcd]);
        for _ in 0..2 {
            body.extend_from_slice(&[1, 0]);
            body.extend(std::iter::repeat_n(0x42u8, 32));
        }
        packet(TAG_SIGNATURE, &body)
    }

    #[test]
    fn a_subkey_with_a_forged_binding_is_left_out() {
        // the EC key appended to the Ed25519 keyring as a subkey of it,
        // with a binding that names the Ed25519 key but is not by it
        let victim = keys(fixture!("key-ed.gpg"));
        let ec_primary = packets(fixture!("key-ec.gpg")).unwrap().remove(0).body;
        let mut ring = fixture!("key-ed.gpg").to_vec();
        ring.extend(packet(TAG_PUBLIC_SUBKEY, &ec_primary));
        ring.extend(forged(
            0x18,
            ALGO_EDDSA_LEGACY,
            Some(0x02),
            None,
            &victim[0].fingerprint,
        ));
        let k = parse_keyring(&ring).unwrap();
        assert_eq!(k.len(), 1, "{k:?}");
        assert!(verify_message(&k, fixture!("msg-ec.sig"), NOW).is_err());
        // the genuine signing subkey still works
        verify_message(&keys(fixture!("key-sub.gpg")), fixture!("msg-sub.sig"), NOW).unwrap();
    }

    #[test]
    fn a_forged_newer_self_signature_changes_nothing() {
        let old = keys(fixture!("key-old.gpg"));
        let mut ring = fixture!("key-old.gpg").to_vec();
        // newer, no expiry: after the user ID's genuine self-signature
        ring.extend(forged(
            0x13,
            ALGO_RSA,
            Some(0x03),
            Some(0),
            &old[0].fingerprint,
        ));
        let k = parse_keyring(&ring).unwrap();
        let e = verify_message(&k, fixture!("msg-old.sig"), NOW + 2 * 86400).unwrap_err();
        assert!(e.0.contains("expired"), "{e}");
    }

    #[test]
    fn revocations_that_do_not_parse_revoke() {
        let mut ring = fixture!("key-ec.gpg").to_vec();
        // a key revocation cut short
        ring.extend(packet(TAG_SIGNATURE, &[4, 0x20, ALGO_ECDSA]));
        let e = verify_message(&parse_keyring(&ring).unwrap(), fixture!("msg-ec.sig"), NOW)
            .unwrap_err();
        assert!(e.0.contains("revoked"), "{e}");
        // a revocation with an unknown critical subpacket
        let mut ring = fixture!("key-ec.gpg").to_vec();
        ring.extend(packet(
            TAG_SIGNATURE,
            &[4, 0x20, ALGO_ECDSA, 8, 0, 2, 1, 0x80 | 100, 0, 0],
        ));
        assert!(
            verify_message(&parse_keyring(&ring).unwrap(), fixture!("msg-ec.sig"), NOW).is_err()
        );
        // a signature packet whose type cannot be read refuses the keyring
        let mut ring = fixture!("key-ec.gpg").to_vec();
        ring.extend(packet(TAG_SIGNATURE, &[4]));
        assert!(parse_keyring(&ring).is_err());
        // a subkey revocation that does not parse revokes the subkey only
        let mut ring = fixture!("key-sub.gpg").to_vec();
        ring.extend(packet(TAG_SIGNATURE, &[4, 0x28]));
        let e = verify_message(&parse_keyring(&ring).unwrap(), fixture!("msg-sub.sig"), NOW)
            .unwrap_err();
        assert!(e.0.contains("revoked"), "{e}");
    }

    #[test]
    fn a_subkey_does_not_outlive_its_primary() {
        // made 1791743906: the primary certifies only, expires a day later
        let created = 1_791_743_906;
        let k = keys(fixture!("key-pexp.gpg"));
        verify_message(&k, fixture!("msg-pexp.sig"), created + 60).unwrap();
        let e = verify_message(&k, fixture!("msg-pexp.sig"), created + 2 * 86400).unwrap_err();
        assert!(e.0.contains("primary key"), "{e}");
    }

    #[test]
    fn keyrings_of_garbage_fail_cleanly() {
        for data in [
            &b""[..],
            b"\x99",
            b"hello",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!\n",
        ] {
            let _ = parse_keyring(data);
        }
        let k = fixture!("key-rsa.gpg");
        for n in 0..k.len() {
            let _ = parse_keyring(&k[..n]);
        }
    }

    // The reading of packets and signature fields, pinned as it is.

    /// An old format packet of `tag`; `lt` is the length type: 0, 1 and 2
    /// give a length of 1, 2 and 4 octets, 3 has none (up to the end).
    fn old(tag: u8, lt: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80 | (tag << 2) | lt];
        match lt {
            0 => out.push(body.len() as u8),
            1 => out.extend_from_slice(&(body.len() as u16).to_be_bytes()),
            2 => out.extend_from_slice(&(body.len() as u32).to_be_bytes()),
            _ => {}
        }
        out.extend_from_slice(body);
        out
    }

    fn file(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/signature/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn texts(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
        packets(data)
            .map(|v| v.into_iter().map(|p| (p.tag, p.body)).collect())
            .map_err(|e| e.0)
    }

    #[test]
    fn packets_of_every_length_form() {
        let body = vec![7u8; 300];
        for lt in 0..3 {
            let b = if lt == 0 { &body[..100] } else { &body[..] };
            assert_eq!(texts(&old(6, lt, b)).unwrap(), [(6, b.to_vec())]);
        }
        // up to the end of the data
        assert_eq!(texts(&old(11, 3, &body)).unwrap(), [(11, body.clone())]);
        let mut two = old(6, 0, b"ab");
        two.extend(old(13, 3, b"rest"));
        assert_eq!(
            texts(&two).unwrap(),
            [(6, b"ab".to_vec()), (13, b"rest".to_vec())]
        );
        // new format: one octet up to 191, two octets from 192 to 8383,
        // five octets for any
        for (n, head) in [
            (0, vec![0]),
            (191, vec![191]),
            (192, vec![192, 0]),
            (8383, vec![223, 255]),
        ] {
            let mut p = vec![0xc0 | 6];
            p.extend(head);
            p.extend(vec![1u8; n]);
            assert_eq!(texts(&p).unwrap(), [(6, vec![1u8; n])], "{n}");
        }
        assert_eq!(texts(&packet(6, &body)).unwrap(), [(6, body.clone())]);
        // a five octet length of a short body is as good as a short one
        assert_eq!(texts(&packet(6, b"")).unwrap(), [(6, vec![])]);
    }

    #[test]
    fn partial_lengths_join_for_compressed_and_literal_data_only() {
        // 2^1 and 2^2 octets, then a final length of 3
        let mut p = vec![
            0xc0 | TAG_LITERAL,
            224 | 1,
            1,
            2,
            224 | 2,
            3,
            4,
            5,
            6,
            3,
            7,
            8,
            9,
        ];
        assert_eq!(
            texts(&p).unwrap(),
            [(TAG_LITERAL, vec![1, 2, 3, 4, 5, 6, 7, 8, 9])]
        );
        p[0] = 0xc0 | TAG_COMPRESSED;
        assert!(texts(&p).is_ok());
        for tag in [TAG_SIGNATURE, TAG_PUBLIC_KEY, TAG_USER_ID, TAG_MARKER] {
            p[0] = 0xc0 | tag;
            assert_eq!(
                texts(&p).unwrap_err(),
                "a partial length for a packet that cannot have one"
            );
        }
        // the partial lengths end only with another kind of length
        let cut = [0xc0 | TAG_LITERAL, 224 | 1, 1, 2];
        assert_eq!(texts(&cut).unwrap_err(), "truncated OpenPGP data");
        // a partial piece longer than what is left
        let lie = [0xc0 | TAG_LITERAL, 224 | 3, 1, 2];
        assert_eq!(texts(&lie).unwrap_err(), "truncated OpenPGP data");
        // the largest, 2^30, is a length like any other
        let big = [0xc0 | TAG_LITERAL, 224 | 30, 1];
        assert_eq!(texts(&big).unwrap_err(), "truncated OpenPGP data");
        // old format has no partial lengths: the type 3 reads to the end
        assert_eq!(
            texts(&[0x80 | (TAG_LITERAL << 2) | 3, 0xe1, 1]).unwrap(),
            [(TAG_LITERAL, vec![0xe1, 1])]
        );
    }

    #[test]
    fn zero_length_packets_and_the_empty_input() {
        assert_eq!(texts(b"").unwrap(), []);
        let mut all = old(2, 0, b"");
        all.extend(old(2, 1, b""));
        all.extend(old(2, 2, b""));
        all.extend(old(2, 3, b""));
        all.extend([0xc2, 0]);
        // the type 3 packet takes what follows: it is the last
        assert_eq!(texts(&all).unwrap().len(), 4);
        let mut all = old(2, 0, b"");
        all.extend(old(2, 1, b""));
        all.extend(old(2, 2, b""));
        all.extend([0xc2, 0]);
        assert_eq!(texts(&all).unwrap(), vec![(2, vec![]); 4]);
    }

    #[test]
    fn the_number_of_packets_is_bounded() {
        let at_most: Vec<u8> = std::iter::repeat_n([0xc2, 0], MAX_PACKETS)
            .flatten()
            .collect();
        assert_eq!(packets(&at_most).unwrap().len(), MAX_PACKETS);
        let mut more = at_most.clone();
        more.extend([0xc2, 0]);
        assert_eq!(texts(&more).unwrap_err(), "too many OpenPGP packets");
        // the one too many is refused before it is read
        let mut more = at_most;
        more.push(0x00);
        assert_eq!(texts(&more).unwrap_err(), "too many OpenPGP packets");
    }

    #[test]
    fn lengths_that_lie_and_bytes_that_are_no_packet() {
        let t = "truncated OpenPGP data";
        for (data, want) in [
            (&[0x80 | (6 << 2)][..], t),
            (&[0x80 | (6 << 2) | 1, 0], t),
            (&[0x80 | (6 << 2) | 2, 0, 0, 0], t),
            (&[0x80 | (6 << 2), 2, 1], t),
            (&[0x80 | (6 << 2) | 2, 0xff, 0xff, 0xff, 0xff, 1], t),
            (&[0xc6], t),
            (&[0xc6, 2, 1], t),
            (&[0xc6, 192], t),
            (&[0xc6, 223, 255, 1], t),
            (&[0xc6, 255, 0, 0, 0], t),
            (&[0xc6, 255, 0, 0, 0, 2, 1], t),
            (&[0xc6, 255, 0xff, 0xff, 0xff, 0xff, 1], t),
            // no high bit: not a packet
            (&[0x00], "not an OpenPGP packet"),
            (&[0x7f, 0], "not an OpenPGP packet"),
            // trailing garbage after good packets is refused, never ignored
            (&[0xc6, 0, 0x00], "not an OpenPGP packet"),
            (&[0xc6, 0, 0xc6], t),
        ] {
            assert_eq!(texts(data).unwrap_err(), want, "{data:02x?}");
        }
    }

    #[test]
    fn real_files_cut_at_every_byte() {
        for name in [
            "key-rsa.gpg",
            "key-ed.gpg",
            "key-ec.gpg",
            "key-sub.gpg",
            "key-old.gpg",
            "msg-rsa.sig",
            "msg-ed.sig",
            "msg-ec.sig",
            "msg-sub.sig",
        ] {
            let data = file(name);
            let whole = texts(&data).unwrap();
            for n in 0..data.len() {
                // a cut is refused, or it falls between two packets and
                // leaves the packets before it
                if let Ok(part) = texts(&data[..n]) {
                    // an old format packet of no length takes what is there
                    let Some((last, init)) = part.split_last() else {
                        continue;
                    };
                    assert!(whole.starts_with(init), "{name} cut at {n}");
                    if let Some(w) = whole.get(init.len()) {
                        assert!(w.0 == last.0 && w.1.starts_with(&last.1), "{name} {n}");
                    }
                }
            }
        }
    }

    /// The body of a signature packet by the Ed25519 key `key`: `data` is
    /// what it hashes before the subpackets.
    fn ed_signature(
        key: &PKey<openssl::pkey::Private>,
        sig_type: u8,
        data: &[u8],
        hashed: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![4, sig_type, ALGO_ED25519, 8];
        body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        body.extend_from_slice(hashed);
        let mut h = openssl::hash::Hasher::new(MessageDigest::sha256()).unwrap();
        h.update(data).unwrap();
        h.update(&body).unwrap();
        h.update(&[4, 0xff]).unwrap();
        h.update(&(body.len() as u32).to_be_bytes()).unwrap();
        let digest = h.finish().unwrap();
        let sig = openssl::sign::Signer::new_without_digest(key)
            .unwrap()
            .sign_oneshot_to_vec(&digest)
            .unwrap();
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&digest[..2]);
        body.extend(sig);
        body
    }

    /// A keyring of one Ed25519 key whose user ID is certified with the
    /// key flags subpacket `flags` (none: no such subpacket), and a signed
    /// message of `PAYLOAD` by it; `cert_extra` and `msg_extra` are more
    /// hashed subpackets of the two signatures.
    fn self_made(flags: Option<&[u8]>, cert_extra: &[u8], msg_extra: &[u8]) -> (Vec<Key>, Vec<u8>) {
        let key = PKey::generate_ed25519().unwrap();
        let created = (NOW - 1000) as u32;
        let mut public = vec![4];
        public.extend_from_slice(&created.to_be_bytes());
        public.push(ALGO_ED25519);
        public.extend(key.raw_public_key().unwrap());
        let uid = b"a <a@example.com>";
        let mut data = framed_key(&public).unwrap();
        data.extend(framed_id(TAG_USER_ID, uid).unwrap());
        let mut hashed = sp(2, &created.to_be_bytes());
        if let Some(f) = flags {
            hashed.extend(sp(27, f));
        }
        hashed.extend_from_slice(cert_extra);
        let mut ring = packet(TAG_PUBLIC_KEY, &public);
        ring.extend(packet(TAG_USER_ID, uid));
        ring.extend(packet(
            TAG_SIGNATURE,
            &ed_signature(&key, 0x13, &data, &hashed),
        ));
        let mut hashed = sp(2, &(NOW as u32).to_be_bytes());
        hashed.extend_from_slice(msg_extra);
        let mut msg = literal(PAYLOAD);
        msg.extend(packet(
            TAG_SIGNATURE,
            &ed_signature(&key, 0, PAYLOAD, &hashed),
        ));
        (parse_keyring(&ring).unwrap(), msg)
    }

    /// A keyring of an Ed25519 primary key that certifies and a signing
    /// subkey, and a message signed by the subkey.  `primary_extra`,
    /// `binding_extra` and `back_extra` are more hashed subpackets of the
    /// self-signature, the binding and the back-signature.
    fn with_subkey(
        primary_extra: &[u8],
        binding_extra: &[u8],
        back_extra: &[u8],
    ) -> (Vec<Key>, Vec<u8>) {
        let created = (NOW - 1000) as u32;
        let public = |key: &PKey<openssl::pkey::Private>| {
            let mut p = vec![4];
            p.extend_from_slice(&created.to_be_bytes());
            p.push(ALGO_ED25519);
            p.extend(key.raw_public_key().unwrap());
            p
        };
        let (primary, subkey) = (
            PKey::generate_ed25519().unwrap(),
            PKey::generate_ed25519().unwrap(),
        );
        let (pub_primary, pub_sub) = (public(&primary), public(&subkey));
        let uid = b"a <a@example.com>";
        let mut uid_data = framed_key(&pub_primary).unwrap();
        uid_data.extend(framed_id(TAG_USER_ID, uid).unwrap());
        let mut hashed = sp(2, &created.to_be_bytes());
        hashed.extend(sp(27, &[0x01]));
        hashed.extend_from_slice(primary_extra);
        let mut key_data = framed_key(&pub_primary).unwrap();
        key_data.extend(framed_key(&pub_sub).unwrap());
        let mut back_hashed = sp(2, &created.to_be_bytes());
        back_hashed.extend_from_slice(back_extra);
        let back = ed_signature(&subkey, 0x19, &key_data, &back_hashed);
        let mut bind_hashed = sp(2, &created.to_be_bytes());
        bind_hashed.extend(sp(27, &[0x02]));
        bind_hashed.extend_from_slice(binding_extra);
        let mut unhashed = vec![];
        unhashed.extend(sp(32, &back));
        let mut binding = ed_signature(&primary, 0x18, &key_data, &bind_hashed);
        append_unhashed(&mut binding, &unhashed);
        let mut ring = packet(TAG_PUBLIC_KEY, &pub_primary);
        ring.extend(packet(TAG_USER_ID, uid));
        ring.extend(packet(
            TAG_SIGNATURE,
            &ed_signature(&primary, 0x13, &uid_data, &hashed),
        ));
        ring.extend(packet(TAG_PUBLIC_SUBKEY, &pub_sub));
        ring.extend(packet(TAG_SIGNATURE, &binding));
        let mut msg = literal(PAYLOAD);
        let hashed = sp(2, &(NOW as u32).to_be_bytes());
        msg.extend(packet(
            TAG_SIGNATURE,
            &ed_signature(&subkey, 0, PAYLOAD, &hashed),
        ));
        (parse_keyring(&ring).unwrap(), msg)
    }

    /// A subpacket of a one octet length.
    fn sp(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![(value.len() + 1) as u8, kind];
        out.extend_from_slice(value);
        out
    }

    /// A notation subpacket: flags, the lengths of the name and the value,
    /// then both.
    fn notation(critical: bool, name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut v = vec![0x80, 0, 0, 0, 0, name.len() as u8, 0, value.len() as u8];
        v.extend_from_slice(name);
        v.extend_from_slice(value);
        sp(if critical { 0x80 | 20 } else { 20 }, &v)
    }

    #[test]
    fn a_critical_notation_refuses_the_signature_that_has_it() {
        let critical = notation(true, b"hold@example.com", b"1");
        let plain = notation(false, b"hold@example.com", b"1");
        // a notation that is not critical is a note
        let (k, msg) = self_made(None, &plain, &plain);
        verify_message(&k, &msg, NOW).unwrap();
        // in the message signature
        let (k, msg) = self_made(None, &[], &critical);
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert_eq!(e.0, "an unknown critical signature subpacket 20");
        // in the self-signature of the key: it does not count, so the key
        // has no valid self-signature and cannot sign
        let (k, msg) = self_made(None, &critical, &[]);
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert!(e.0.contains("is not for signing"), "{e}");
        // in the unhashed part it is not the signer's: it counts for nothing
        assert!(parse_signature(&sig_body(&[], &critical)).is_ok());
        // in the binding of a subkey: the subkey is left out
        let (k, _) = with_subkey(&[], &critical, &[]);
        assert_eq!(k.len(), 1);
        // in its back-signature: the subkey cannot sign
        let (k, msg) = with_subkey(&[], &[], &critical);
        assert_eq!(k.len(), 2);
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert!(e.0.contains("is not for signing"), "{e}");
        // without it the subkey signs
        let (k, msg) = with_subkey(&[], &plain, &plain);
        verify_message(&k, &msg, NOW).unwrap();
    }

    #[test]
    fn what_the_key_flags_of_a_self_signature_allow() {
        // no flags subpacket: the key may do what its algorithm does
        for flags in [None, Some(&[0x03][..]), Some(&[0x02, 0xff])] {
            let (k, msg) = self_made(flags, &[], &[]);
            assert_eq!(k.len(), 1);
            verify_message(&k, &msg, NOW).unwrap();
        }
        // flags that do not say signing, or say nothing at all
        for flags in [&[0x01][..], &[0x00], &[]] {
            let (k, msg) = self_made(Some(flags), &[], &[]);
            let got = verify_message(&k, &msg, NOW);
            let e = got.err().unwrap_or_else(|| panic!("{flags:02x?} signs"));
            assert!(e.0.contains("is not for signing"), "{flags:02x?}: {e}");
        }
    }

    /// The body of a v4 Ed25519 signature packet with these subpacket areas.
    fn sig_body(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
        let mut body = vec![4, 0, ALGO_ED25519, 8];
        body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        body.extend_from_slice(hashed);
        body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
        body.extend_from_slice(unhashed);
        body.extend_from_slice(&[0xab, 0xcd]);
        body.extend(std::iter::repeat_n(0x11u8, 64));
        body
    }

    fn sig_err(body: &[u8]) -> String {
        parse_signature(body).err().expect("refused").0
    }

    /// The signature packets of a file, in order.
    fn sig_bodies(name: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for p in packets(&file(name)).unwrap() {
            if p.tag == TAG_COMPRESSED {
                // the signature of `msg-rsa.sig` is inside
                let mut inner = Vec::new();
                match p.body[0] {
                    1 => flate2::read::DeflateDecoder::new(&p.body[1..]).read_to_end(&mut inner),
                    _ => flate2::read::ZlibDecoder::new(&p.body[1..]).read_to_end(&mut inner),
                }
                .unwrap();
                out.extend(
                    packets(&inner)
                        .unwrap()
                        .into_iter()
                        .filter(|p| p.tag == TAG_SIGNATURE)
                        .map(|p| p.body),
                );
            } else if p.tag == TAG_SIGNATURE {
                out.push(p.body);
            }
        }
        out
    }

    #[test]
    fn the_fields_of_real_signatures() {
        for (name, algo) in [
            ("msg-rsa.sig", ALGO_RSA),
            ("msg-ed.sig", ALGO_EDDSA_LEGACY),
            ("msg-ec.sig", ALGO_ECDSA),
        ] {
            let bodies = sig_bodies(name);
            assert_eq!(bodies.len(), 1, "{name}");
            let sig = parse_signature(&bodies[0]).unwrap();
            assert_eq!((sig.sig_type, sig.algo, sig.hash), (0, algo, sig.hash));
            assert!(sig.sub.created.is_some(), "{name}");
            assert!(sig.sub.issuer.is_some() || sig.sub.issuer_fpr.is_some());
            assert_eq!(sig.mpis.len(), if algo == ALGO_RSA { 1 } else { 2 });
            let hashed_len = usize::from(u16::from_be_bytes([bodies[0][4], bodies[0][5]]));
            assert_eq!(sig.trailer.len(), 6 + hashed_len + 6);
            assert_eq!(sig.trailer[..6 + hashed_len], bodies[0][..6 + hashed_len]);
            // every cut of the packet body is refused
            for n in 0..bodies[0].len() {
                assert!(parse_signature(&bodies[0][..n]).is_err(), "{name} {n}");
            }
        }
        // a binding signature of a subkey carries the back-signature
        let sigs = sig_bodies("key-sub.gpg");
        let sub = sigs
            .iter()
            .map(|b| parse_signature(b).unwrap())
            .find(|s| s.sig_type == 0x18)
            .unwrap();
        assert_eq!(sub.sub.key_flags.map(|f| f & 2), Some(2));
        assert_eq!(sub.sub.embedded.len(), 1);
    }

    #[test]
    fn creation_time_expiry_and_flags_are_of_the_hashed_part_only() {
        let t = |v: u32| v.to_be_bytes();
        let mut hashed = sp(2, &t(1000));
        hashed.extend(sp(3, &t(50)));
        hashed.extend(sp(9, &t(60)));
        hashed.extend(sp(27, &[0x02]));
        let sub = parse_signature(&sig_body(&hashed, b"")).unwrap().sub;
        assert_eq!(
            (sub.created, sub.expires, sub.key_expires, sub.key_flags),
            (Some(1000), Some(50), Some(60), Some(2))
        );
        // the same in the unhashed part says nothing
        let sub = parse_signature(&sig_body(b"", &hashed)).unwrap().sub;
        assert_eq!(
            (sub.created, sub.expires, sub.key_expires, sub.key_flags),
            (None, None, None, None)
        );
        // and does not change what the hashed part says
        let mut unhashed = sp(2, &t(1));
        unhashed.extend(sp(3, &t(1)));
        unhashed.extend(sp(9, &t(1)));
        unhashed.extend(sp(27, &[0xff]));
        let sub = parse_signature(&sig_body(&hashed, &unhashed)).unwrap().sub;
        assert_eq!(
            (sub.created, sub.expires, sub.key_expires, sub.key_flags),
            (Some(1000), Some(50), Some(60), Some(2))
        );
        // a creation time in the unhashed part only: none
        let sub = parse_signature(&sig_body(&sp(3, &t(5)), &sp(2, &t(1000))))
            .unwrap()
            .sub;
        assert_eq!((sub.created, sub.expires), (None, Some(5)));
    }

    #[test]
    fn a_duplicate_hashed_subpacket_is_taken_from_the_last() {
        let t = |v: u32| v.to_be_bytes();
        let mut hashed = sp(2, &t(1000));
        hashed.extend(sp(2, &t(2000)));
        hashed.extend(sp(27, &[0x02]));
        // empty flags are flags of 0: they replace the ones before them
        hashed.extend(sp(27, &[]));
        let sub = parse_signature(&sig_body(&hashed, b"")).unwrap().sub;
        assert_eq!((sub.created, sub.key_flags), (Some(2000), Some(0)));
        // the first octet of the flags is the flags
        let sub = parse_signature(&sig_body(&sp(27, &[0x02, 0xff]), b""))
            .unwrap()
            .sub;
        assert_eq!(sub.key_flags, Some(2));
    }

    #[test]
    fn a_time_subpacket_of_another_size_is_refused_in_the_hashed_part_only() {
        for kind in [2, 3, 9] {
            for value in [&[][..], &[1, 2, 3], &[1, 2, 3, 4, 5]] {
                let bad = sp(kind, value);
                assert_eq!(
                    sig_err(&sig_body(&bad, b"")),
                    "an invalid time subpacket",
                    "{kind}"
                );
                assert!(parse_signature(&sig_body(b"", &bad)).is_ok());
            }
        }
    }

    #[test]
    fn an_unknown_critical_subpacket_refuses_the_signature_in_the_hashed_part() {
        // 0, 1, 3 and 8 are not subpackets, 100 neither; a critical bit
        // on those, and on the reserved and the unsupported ones
        for kind in [0u8, 1, 6, 8, 13, 14, 15, 17, 18, 19, 24, 35, 100, 127] {
            let critical = sp(0x80 | kind, &[1, 2]);
            assert_eq!(
                sig_err(&sig_body(&critical, b"")),
                format!("an unknown critical signature subpacket {kind}"),
                "{kind}"
            );
            // not critical: ignored
            assert!(parse_signature(&sig_body(&sp(kind, &[1, 2]), b"")).is_ok());
            // critical in the unhashed part: the signer did not say it
            assert!(parse_signature(&sig_body(b"", &critical)).is_ok(), "{kind}");
        }
        // the ones that are known are accepted with the bit
        for kind in [4u8, 5, 7, 11, 12, 21, 22, 23, 25, 26, 28, 29, 30, 31, 34] {
            let known = sp(0x80 | kind, &[1, 2]);
            assert!(parse_signature(&sig_body(&known, b"")).is_ok(), "{kind}");
        }
        // an unknown critical subpacket after good ones, and after a
        // creation time
        let mut hashed = sp(2, &1000u32.to_be_bytes());
        hashed.extend(sp(0x80 | 100, &[]));
        assert!(sig_err(&sig_body(&hashed, b"")).contains("critical"));
        // the critical bit on what is read is no different
        let mut hashed = sp(0x80 | 2, &1000u32.to_be_bytes());
        hashed.extend(sp(0x80 | 16, &[1; 8]));
        let sub = parse_signature(&sig_body(&hashed, b"")).unwrap().sub;
        assert_eq!((sub.created, sub.issuer), (Some(1000), Some([1; 8])));
    }

    #[test]
    fn the_issuer_is_taken_from_either_part_and_is_a_hint() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let hashed = sp(16, &id);
        let a = parse_signature(&sig_body(&hashed, b"")).unwrap().sub;
        let b = parse_signature(&sig_body(b"", &hashed)).unwrap().sub;
        assert_eq!((a.issuer, b.issuer), (Some(id), Some(id)));
        // the last one wins, whichever part it is in
        let c = parse_signature(&sig_body(&hashed, &sp(16, &[9; 8])))
            .unwrap()
            .sub;
        assert_eq!(c.issuer, Some([9; 8]));
        // a size that is not 8 is ignored
        let d = parse_signature(&sig_body(&sp(16, &[1; 7]), b""))
            .unwrap()
            .sub;
        assert_eq!(d.issuer, None);
        // the fingerprint: version 4 and then any octets
        let mut fpr = vec![4];
        fpr.extend([0xaa; 20]);
        for (value, want) in [
            (&fpr[..], Some(fpr[1..].to_vec())),
            (&[4][..], Some(vec![])),
            (&[5, 1][..], None),
            (&[][..], None),
        ] {
            let s = parse_signature(&sig_body(b"", &sp(33, value))).unwrap().sub;
            assert_eq!(s.issuer_fpr, want);
        }
        // embedded signatures: of either part
        let s = parse_signature(&sig_body(&sp(32, &[1, 2]), &sp(32, &[3])))
            .unwrap()
            .sub;
        assert_eq!(s.embedded, [vec![1, 2], vec![3]]);
    }

    #[test]
    fn subpacket_lengths_of_every_form_and_lies() {
        // two octets: 192 bytes, the kind and 191 of value
        let mut long = vec![192, 0, 0x80 | 26];
        long.extend(vec![0u8; 191]);
        assert!(parse_signature(&sig_body(&long, b"")).is_ok());
        // five octets, even for a short one
        let five = [255, 0, 0, 0, 2, 26, 0];
        assert!(parse_signature(&sig_body(&five, b"")).is_ok());
        let five_time = [255, 0, 0, 0, 5, 2, 0, 0, 3, 232];
        let sub = parse_signature(&sig_body(&five_time, b"")).unwrap().sub;
        assert_eq!(sub.created, Some(1000));
        // a length of zero
        for a in [vec![0u8], sp(2, &[0; 4]).into_iter().chain([0]).collect()] {
            assert_eq!(sig_err(&sig_body(&a, b"")), "an empty signature subpacket");
            assert_eq!(sig_err(&sig_body(b"", &a)), "an empty signature subpacket");
        }
        // a length past the area, even when the signature has the bytes
        for lie in [
            vec![5, 26, 0],
            vec![2],
            vec![192],
            vec![192, 0, 26],
            vec![255, 0, 0, 0],
            vec![255, 0, 0, 0, 9, 26],
            vec![255, 255, 255, 255, 255, 26],
        ] {
            assert_eq!(sig_err(&sig_body(&lie, b"")), "truncated OpenPGP data");
            assert_eq!(sig_err(&sig_body(b"", &lie)), "truncated OpenPGP data");
        }
        // the bytes after the area are the signature's, not the area's
        let mut body = sig_body(&[1, 26], b"");
        assert!(parse_signature(&body).is_ok());
        body[5] = 1;
        assert_eq!(sig_err(&body), "truncated OpenPGP data");
    }

    #[test]
    fn the_areas_and_the_values_of_a_signature_are_bounded() {
        let body = sig_body(&sp(2, &[0; 4]), &sp(26, &[1]));
        // every cut
        for n in 0..body.len() {
            assert!(parse_signature(&body[..n]).is_err(), "{n}");
        }
        // bytes after the signature value are not looked at
        let mut more = body.clone();
        more.extend([1, 2, 3]);
        assert!(parse_signature(&more).is_ok());
        // an area longer than the packet
        let mut lie = body.clone();
        lie[4] = 0xff;
        lie[5] = 0xff;
        assert_eq!(sig_err(&lie), "truncated OpenPGP data");
        // the algorithm decides the values: RSA has one, DSA two
        let rsa = |algo: u8, mpis: &[&[u8]]| {
            let mut b = vec![4, 0, algo, 8, 0, 0, 0, 0, 0xab, 0xcd];
            for m in mpis {
                b.extend_from_slice(&((m.len() * 8) as u16).to_be_bytes());
                b.extend_from_slice(m);
            }
            b
        };
        assert_eq!(
            parse_signature(&rsa(1, &[&[7; 4]])).unwrap().mpis,
            [vec![7; 4]]
        );
        assert_eq!(parse_signature(&rsa(3, &[&[7; 4]])).unwrap().mpis.len(), 1);
        for algo in [17, 19, 22] {
            let two = parse_signature(&rsa(algo, &[&[1; 2], &[2; 3]])).unwrap();
            assert_eq!(two.mpis, [vec![1; 2], vec![2; 3]]);
            assert_eq!(sig_err(&rsa(algo, &[&[1; 2]])), "truncated OpenPGP data");
        }
        // the bit count rounds up, and the leading bits are not checked
        let mut odd = rsa(1, &[]);
        odd.extend([0, 9, 0xff, 0xff]);
        assert_eq!(parse_signature(&odd).unwrap().mpis, [vec![0xff, 0xff]]);
        let mut zero = rsa(1, &[]);
        zero.extend([0, 0]);
        assert_eq!(parse_signature(&zero).unwrap().mpis, [Vec::<u8>::new()]);
        let mut short = rsa(1, &[]);
        short.extend([0xff, 0xff, 1]);
        assert_eq!(sig_err(&short), "truncated OpenPGP data");
        for algo in [0u8, 2, 16, 18, 20, 21, 23, 28, 255] {
            assert_eq!(
                sig_err(&rsa(algo, &[&[1]])),
                format!("unsupported signature algorithm {algo}")
            );
        }
    }

    #[test]
    fn signatures_of_other_versions_are_refused() {
        let mut body = sig_body(&sp(2, &[0; 4]), b"");
        for v in [0u8, 1, 2, 3, 5, 6, 255] {
            body[0] = v;
            assert_eq!(
                sig_err(&body),
                format!("version {v} signatures are not supported")
            );
        }
        // a v3 packet: version, length 5, type, time, issuer, algorithm,
        // hash, left 16 bits, the value
        let mut v3 = vec![
            3, 5, 0, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 1, 8, 0xab, 0xcd,
        ];
        v3.extend([0, 8, 0xff]);
        assert_eq!(sig_err(&v3), "version 3 signatures are not supported");
        assert_eq!(sig_err(&[]), "truncated OpenPGP data");
        assert_eq!(sig_err(&[4]), "truncated OpenPGP data");
        // what a keyring says of the type of one that does not parse
        assert_eq!(signature_type(&v3), Some(0));
        assert_eq!(signature_type(&[4, 0x18]), Some(0x18));
        assert_eq!(signature_type(&[3]), None);
        assert_eq!(signature_type(&[]), None);
    }

    /// The message `msg-ed.sig` with `edit` applied to the body of its
    /// signature packet.
    fn edited_message(edit: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let data = fixture!("msg-ed.sig");
        let mut out = Vec::new();
        for mut p in packets(data).unwrap() {
            if p.tag == TAG_SIGNATURE {
                edit(&mut p.body);
            }
            out.extend(packet(p.tag, &p.body));
        }
        out
    }

    /// The signature body with `extra` after its unhashed subpackets.
    fn append_unhashed(body: &mut Vec<u8>, extra: &[u8]) {
        let hashed = usize::from(u16::from_be_bytes([body[4], body[5]]));
        let at = 6 + hashed;
        let unhashed = u16::from_be_bytes([body[at], body[at + 1]]);
        let end = at + 2 + usize::from(unhashed);
        body.splice(end..end, extra.iter().copied());
        let new = unhashed + extra.len() as u16;
        body[at..at + 2].copy_from_slice(&new.to_be_bytes());
    }

    #[test]
    fn what_is_appended_to_the_unhashed_part_of_a_valid_signature() {
        let k = keys(fixture!("key-ed.gpg"));
        let plain = edited_message(|_| {});
        verify_message(&k, &plain, NOW).unwrap();
        // a creation time before the key, an expiry in the past, another
        // issuer, flags: none of them is the signer's
        let mut extra = sp(2, &1u32.to_be_bytes());
        extra.extend(sp(3, &1u32.to_be_bytes()));
        extra.extend(sp(9, &1u32.to_be_bytes()));
        extra.extend(sp(27, &[0]));
        extra.extend(sp(16, &[9; 8]));
        extra.extend(sp(0x80 | 100, &[1]));
        let msg = edited_message(|b| append_unhashed(b, &extra));
        let (content, by) = verify_message(&k, &msg, NOW).unwrap();
        assert_eq!(content, PAYLOAD);
        assert_eq!(by.fingerprint, k[0].fingerprint);
        // anything in the hashed part is not what was signed
        let msg = edited_message(|b| {
            let hashed = usize::from(u16::from_be_bytes([b[4], b[5]]));
            b.splice(6 + hashed..6 + hashed, sp(26, &[1]));
            let new = (hashed + 3) as u16;
            b[4..6].copy_from_slice(&new.to_be_bytes());
        });
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert!(e.0.contains("no trusted key"), "{e}");
        // an unknown critical subpacket there refuses it before that
        let msg = edited_message(|b| {
            let hashed = usize::from(u16::from_be_bytes([b[4], b[5]]));
            b.splice(6 + hashed..6 + hashed, sp(0x80 | 100, &[1]));
            let new = (hashed + 3) as u16;
            b[4..6].copy_from_slice(&new.to_be_bytes());
        });
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert_eq!(e.0, "an unknown critical signature subpacket 100");
    }

    #[test]
    fn a_signature_without_a_hashed_creation_time_is_not_used() {
        let k = keys(fixture!("key-ed.gpg"));
        // the creation time only where the signer did not say it
        let body = sig_body(&sp(16, &[1; 8]), &sp(2, &(NOW as u32).to_be_bytes()));
        let mut msg = literal(PAYLOAD);
        msg.extend(packet(TAG_SIGNATURE, &body));
        let e = verify_message(&k, &msg, NOW).unwrap_err();
        assert_eq!(e.0, "a signature without its creation time");
    }

    #[test]
    fn the_signed_message_is_read_with_its_limits() {
        let k = keys(fixture!("key-ed.gpg"));
        // more packets than a message has
        let many: Vec<u8> = std::iter::repeat_n(old(TAG_ONE_PASS, 0, b""), 65)
            .flatten()
            .collect();
        let e = verify_message(&k, &many, NOW).unwrap_err();
        assert_eq!(e.0, "a signed message with too many packets");
        let e = verify_message(&k, &old(TAG_ONE_PASS, 0, b""), NOW).unwrap_err();
        assert_eq!(e.0, "the signature has no signed content");
        let mut m = literal(b"x");
        m.extend(literal(b"y"));
        let e = verify_message(&k, &m, NOW).unwrap_err();
        assert_eq!(e.0, "a message with two literal data packets");
        let e = verify_message(&k, &literal(b"x"), NOW).unwrap_err();
        assert_eq!(e.0, "the message is not signed");
        let mut m = literal(b"x");
        m.extend(packet(TAG_SIGNATURE, &[3, 5]));
        let e = verify_message(&k, &m, NOW).unwrap_err();
        assert_eq!(e.0, "version 3 signatures are not supported");
        // trailing garbage after the signature
        let mut m = fixture!("msg-ed.sig").to_vec();
        m.push(0);
        let e = verify_message(&k, &m, NOW).unwrap_err();
        assert_eq!(e.0, "not an OpenPGP packet");
        // a literal packet whose header is cut
        for body in [&[][..], b"b", &[b'b', 5, 1], &[b'b', 0, 1, 2, 3]] {
            let e = verify_message(&k, &packet(TAG_LITERAL, body), NOW).unwrap_err();
            assert_eq!(e.0, "truncated OpenPGP data");
        }
    }
}
