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

/// Largest signed content (the JSON of a simple signing signature is
/// a few hundred bytes), and what all the compressed packets of a message
/// may inflate to together.
const MAX_CONTENT: u64 = 4 << 20;
/// Largest compressed or literal data accepted, and nesting of compressed
/// packets.
const MAX_DEPTH: usize = 2;
/// Packets of a message or keyring at most.
const MAX_PACKETS: usize = 100_000;

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

    fn is_empty(&self) -> bool {
        self.data.is_empty()
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

/// The packets of `data`, in order.
fn packets(data: &[u8]) -> Result<Vec<Packet>, Error> {
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    while !c.is_empty() {
        if out.len() >= MAX_PACKETS {
            return err("too many OpenPGP packets");
        }
        let first = c.u8()?;
        if first & 0x80 == 0 {
            return err("not an OpenPGP packet");
        }
        if first & 0x40 == 0 {
            // old format
            let tag = (first >> 2) & 0x0f;
            let len = match first & 0x03 {
                0 => usize::from(c.u8()?),
                1 => usize::from(c.u16()?),
                2 => c.u32()? as usize,
                // indeterminate: up to the end
                _ => c.data.len(),
            };
            out.push(Packet {
                tag,
                body: c.take(len)?.to_vec(),
            });
        } else {
            let tag = first & 0x3f;
            let mut body = Vec::new();
            loop {
                let o1 = c.u8()?;
                match o1 {
                    0..=191 => {
                        body.extend_from_slice(c.take(usize::from(o1))?);
                        break;
                    }
                    192..=223 => {
                        let o2 = c.u8()?;
                        let len = ((usize::from(o1) - 192) << 8) + usize::from(o2) + 192;
                        body.extend_from_slice(c.take(len)?);
                        break;
                    }
                    255 => {
                        let len = c.u32()? as usize;
                        body.extend_from_slice(c.take(len)?);
                        break;
                    }
                    // a partial body: more follows
                    _ => {
                        if !matches!(tag, TAG_COMPRESSED | TAG_LITERAL) {
                            return err("a partial length for a packet that cannot have one");
                        }
                        body.extend_from_slice(c.take(1usize << (o1 & 0x1f))?);
                    }
                }
            }
            out.push(Packet { tag, body });
        }
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
#[derive(Default)]
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

fn parse_subpackets(data: &[u8], hashed: bool, out: &mut Subpackets) -> Result<(), Error> {
    let mut c = Cursor::new(data);
    while !c.is_empty() {
        let o1 = c.u8()?;
        let len = match o1 {
            0..=191 => usize::from(o1),
            192..=254 => ((usize::from(o1) - 192) << 8) + usize::from(c.u8()?) + 192,
            255 => c.u32()? as usize,
        };
        if len == 0 {
            return err("an empty signature subpacket");
        }
        let sp = c.take(len)?;
        let (kind, value) = (sp[0], &sp[1..]);
        let critical = kind & 0x80 != 0;
        let be32 = |v: &[u8]| -> Result<u32, Error> {
            match v {
                [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
                _ => err("an invalid time subpacket"),
            }
        };
        match kind & 0x7f {
            // only what is in the hashed part is said by the signer
            2 if hashed => out.created = Some(be32(value)?),
            3 if hashed => out.expires = Some(be32(value)?),
            9 if hashed => out.key_expires = Some(be32(value)?),
            27 if hashed => out.key_flags = value.first().copied(),
            16 => {
                if let Ok(id) = <[u8; 8]>::try_from(value) {
                    out.issuer = Some(id);
                }
            }
            33 => {
                if let [4, fpr @ ..] = value {
                    out.issuer_fpr = Some(fpr.to_vec());
                }
            }
            32 => out.embedded.push(value.to_vec()),
            // what a verifier must understand to accept the signature;
            // notations, policy URIs, signer's user ID, features and
            // preferences are known, with nothing to check here
            _ if critical
                && hashed
                && !matches!(
                    kind & 0x7f,
                    4 | 5 | 7 | 11 | 12 | 20 | 21 | 22 | 23 | 25 | 26 | 28 | 29 | 30 | 31 | 34
                ) =>
            {
                return err(format!(
                    "an unknown critical signature subpacket {}",
                    kind & 0x7f
                ));
            }
            _ => {}
        }
    }
    Ok(())
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
    let mut c = Cursor::new(body);
    let version = c.u8()?;
    if version != 4 {
        return err(format!("version {version} signatures are not supported"));
    }
    let sig_type = c.u8()?;
    let algo = c.u8()?;
    let hash = c.u8()?;
    let hashed_len = usize::from(c.u16()?);
    let hashed = c.take(hashed_len)?;
    let mut sub = Subpackets::default();
    parse_subpackets(hashed, true, &mut sub)?;
    let unhashed_len = usize::from(c.u16()?);
    parse_subpackets(c.take(unhashed_len)?, false, &mut sub)?;
    let left = c.take(2)?;
    let n_mpis = match algo {
        ALGO_RSA | ALGO_RSA_SIGN => 1,
        ALGO_DSA | ALGO_ECDSA | ALGO_EDDSA_LEGACY => 2,
        ALGO_ED25519 => 0,
        n => return err(format!("unsupported signature algorithm {n}")),
    };
    let mut mpis = Vec::new();
    if algo == ALGO_ED25519 {
        mpis.push(c.take(64)?.to_vec());
    } else {
        for _ in 0..n_mpis {
            mpis.push(c.mpi()?.to_vec());
        }
    }
    let hashed_part = &body[..6 + hashed_len];
    let mut trailer = hashed_part.to_vec();
    trailer.extend_from_slice(&[0x04, 0xff]);
    trailer.extend_from_slice(&(hashed_part.len() as u32).to_be_bytes());
    Ok(Signature {
        sig_type,
        algo,
        hash,
        trailer,
        left16: [left[0], left[1]],
        mpis,
        sub,
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
/// configuration: failing closed is what it would want).
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
}
