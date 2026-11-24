// SPDX-License-Identifier: Apache-2.0
//! The fields of a v4 signature packet (RFC 4880, 5.2.3), and what its
//! subpackets say, with the weight of each area: only the hashed one is
//! the signer's.

use crate::{be, take, Error, Span};

const ALGO_RSA: u8 = 1;
const ALGO_RSA_SIGN: u8 = 3;
const ALGO_DSA: u8 = 17;
const ALGO_ECDSA: u8 = 19;
const ALGO_EDDSA_LEGACY: u8 = 22;
const ALGO_ED25519: u8 = 27;

const SUB_CREATED: u8 = 2;
const SUB_EXPIRES: u8 = 3;
const SUB_KEY_EXPIRES: u8 = 9;
const SUB_ISSUER: u8 = 16;
const SUB_KEY_FLAGS: u8 = 27;
const SUB_EMBEDDED: u8 = 32;
const SUB_ISSUER_FPR: u8 = 33;

/// What the subpackets of a signature say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subpackets {
    /// The times and flags are of the hashed area only.
    pub created: Option<u32>,
    pub expires: Option<u32>,
    pub key_expires: Option<u32>,
    pub key_flags: Option<u8>,
    /// Hints, of either area.
    pub issuer: Option<[u8; 8]>,
    /// The octets after the version of the issuer fingerprint.
    pub issuer_fpr: Option<Span>,
    /// Embedded signatures (the back-signatures of signing subkeys).
    pub embedded: Vec<Span>,
}

/// A v4 signature packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub sig_type: u8,
    pub algo: u8,
    pub hash: u8,
    /// The hashed subpackets.  The bytes from the version to its end are
    /// what the signature hashes after the data.
    pub hashed: Span,
    /// The unhashed subpackets.
    pub unhashed: Span,
    pub left16: [u8; 2],
    /// The values of the signature, as bytes: an integer of its bytes
    /// without the bit count, or the 64 bytes of Ed25519.
    pub values: Vec<Span>,
    pub sub: Subpackets,
}

/// The subpacket kinds that may carry the critical bit although this crate
/// does not read them: they say nothing that a verifier of simple signing
/// has to act on (RFC 4880, 5.2.3.x; RFC 9580: exportable, trust, revocable,
/// preferences, revocation key, key server preferences, primary
/// user ID, policy URI, signer's user ID, reason for revocation, features,
/// signature target, preferred AEAD).
fn known(kind: u8) -> bool {
    matches!(
        kind,
        4 | 5 | 7 | 11 | 12 | 21 | 22 | 23 | 25 | 26 | 28 | 29 | 30 | 31 | 34
    )
}

/// A time subpacket: its value is 4 bytes.
fn time(body: &[u8], value: &Span) -> Result<u32, Error> {
    if value.len != 4 {
        return Err(Error::BadTime);
    }
    let v = be(body, value.off, 4)?;
    Ok(v as u32)
}

/// (Split from `one` only so that each function is small to translate.)
/// The length of the subpacket at `at` (`at < end`) and the offset of its
/// first byte, the kind: the length is the kind byte and the value.  It is
/// at least one and it ends by `end` at the latest.
fn header(body: &[u8], at: usize, end: usize) -> Result<(usize, usize), Error> {
    let o1 = body[at];
    let (len, at) = if o1 < 192 {
        (usize::from(o1), at + 1)
    } else if o1 < 255 {
        if at + 1 >= end {
            return Err(Error::Truncated);
        }
        (
            ((usize::from(o1) - 192) << 8) + usize::from(body[at + 1]) + 192,
            at + 2,
        )
    } else {
        if end - at < 5 {
            return Err(Error::Truncated);
        }
        (be(body, at + 1, 4)?, at + 5)
    };
    if len == 0 {
        return Err(Error::EmptySubpacket);
    }
    if len > end - at {
        return Err(Error::Truncated);
    }
    Ok((len, at))
}

/// The subpacket at `at`, which ends by `end` at the latest: what it says
/// is added to `out`.  The offset after it.
fn one(
    body: &[u8],
    at: usize,
    end: usize,
    hashed: bool,
    out: &mut Subpackets,
) -> Result<usize, Error> {
    let (len, at) = header(body, at, end)?;
    let kind = body[at] & 0x7f;
    let critical = body[at] & 0x80 != 0;
    let value = Span {
        off: at + 1,
        len: len - 1,
    };
    // only what is in the hashed part is said by the signer (the nesting of
    // `if hashed` is written so for the translator)
    if kind == SUB_CREATED {
        if hashed {
            out.created = Some(time(body, &value)?);
        }
    } else if kind == SUB_EXPIRES {
        if hashed {
            out.expires = Some(time(body, &value)?);
        }
    } else if kind == SUB_KEY_EXPIRES {
        if hashed {
            out.key_expires = Some(time(body, &value)?);
        }
    } else if kind == SUB_KEY_FLAGS {
        // flags of no byte have no flag set: they do not say "any use"
        if hashed {
            out.key_flags = if value.len > 0 {
                Some(body[value.off])
            } else {
                Some(0)
            };
        }
    } else if kind == SUB_ISSUER {
        if value.len == 8 {
            let mut id = [0u8; 8];
            id.copy_from_slice(&body[value.off..value.end()]);
            out.issuer = Some(id);
        }
    } else if kind == SUB_ISSUER_FPR {
        if value.len > 0 && body[value.off] == 4 {
            out.issuer_fpr = Some(Span {
                off: value.off + 1,
                len: value.len - 1,
            });
        }
    } else if kind == SUB_EMBEDDED {
        out.embedded.push(value);
    } else if critical && hashed && !known(kind) {
        // what a verifier must understand to accept the signature
        return Err(Error::UnknownCritical(kind));
    }
    Ok(at + len)
}

/// The subpackets of `area` of `body`, the hashed area or not.
pub(crate) fn subpackets(
    body: &[u8],
    area: &Span,
    hashed: bool,
    out: &mut Subpackets,
) -> Result<(), Error> {
    let end = area.end();
    let mut at = area.off;
    let mut fail: Option<Error> = None;
    while fail.is_none() && at < end {
        match one(body, at, end, hashed, out) {
            Ok(next) => at = next,
            Err(e) => fail = Some(e),
        }
    }
    match fail {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// How many integers a signature of the algorithm `algo` has: none for
/// Ed25519, which has 64 bytes as they are.
fn integers(algo: u8) -> Result<usize, Error> {
    match algo {
        ALGO_RSA | ALGO_RSA_SIGN => Ok(1),
        ALGO_DSA | ALGO_ECDSA | ALGO_EDDSA_LEGACY => Ok(2),
        ALGO_ED25519 => Ok(0),
        _ => Err(Error::Algorithm(algo)),
    }
}

/// The values of a signature of `algo` from `at`: its `n` integers, each a
/// bit count and the bytes it needs, or the 64 bytes of Ed25519.
fn values(body: &[u8], at: usize, algo: u8, n: usize) -> Result<Vec<Span>, Error> {
    let mut values: Vec<Span> = Vec::new();
    let mut at = at;
    if algo == ALGO_ED25519 {
        values.push(take(body, at, 64)?);
    }
    let mut fail: Option<Error> = None;
    let mut i = 0;
    while fail.is_none() && i < n {
        match be(body, at, 2) {
            Ok(bits) => match take(body, at + 2, (bits >> 3) + usize::from(bits & 7 != 0)) {
                Ok(v) => {
                    values.push(v);
                    at = v.end();
                }
                Err(e) => fail = Some(e),
            },
            Err(e) => fail = Some(e),
        }
        i += 1;
    }
    match fail {
        Some(e) => Err(e),
        None => Ok(values),
    }
}

/// The signature packet body `body`.
pub fn signature(body: &[u8]) -> Result<Signature, Error> {
    if body.is_empty() {
        return Err(Error::Truncated);
    }
    if body[0] != 4 {
        return Err(Error::Version(body[0]));
    }
    let hashed = take(body, 6, be(body, 4, 2)?)?;
    // (written out, not `default()`, so the translation needs no model of it)
    let mut sub = Subpackets {
        created: None,
        expires: None,
        key_expires: None,
        key_flags: None,
        issuer: None,
        issuer_fpr: None,
        embedded: Vec::new(),
    };
    subpackets(body, &hashed, true, &mut sub)?;
    let unhashed_len = be(body, hashed.end(), 2)?;
    let unhashed = take(body, hashed.end() + 2, unhashed_len)?;
    subpackets(body, &unhashed, false, &mut sub)?;
    let left = take(body, unhashed.end(), 2)?;
    let algo = body[2];
    let n = integers(algo)?;
    let values = values(body, left.end(), algo, n)?;
    Ok(Signature {
        sig_type: body[1],
        algo,
        hash: body[3],
        hashed,
        unhashed,
        left16: [body[left.off], body[left.off + 1]],
        values,
        sub,
    })
}
