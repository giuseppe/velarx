// SPDX-License-Identifier: Apache-2.0
//! The reading of what a signature blob says, before anything is verified.
//! The blob comes from a registry or a file nobody vouched for, and what it
//! says about itself (when it was made, when it expires, which critical
//! rules it asks for) is judged here, on bytes.  What stays in the shell
//! (`velarx-signature`): the hashes and the cryptography, which key may
//! make a signature, the texts of the errors.
//!
//! What is read comes back as spans (offset and length) of the input, never
//! as copies or borrows, so that every claim about where it lies is a claim
//! about numbers.
//!
//! The rules, for every byte string:
//!
//! 1. Nothing panics or reads out of bounds, whatever the bytes and the
//!    sizes.
//!
//! OpenPGP packets (RFC 4880, 4.2; `packets`):
//!
//! 2. A packet begins with a byte with its top bit set.  Bit 6 chooses the
//!    format.  New: the tag is the low 6 bits and the length is of one
//!    octet (up to 191), two octets (192 to 8383) or five octets (255 and
//!    four), or partial (224 to 254: a piece of 2^n bytes follows, then the
//!    next length).  Old: the tag is bits 2 to 5 and the length type is 0,
//!    1 or 2 for a length of 1, 2 or 4 octets, or 3 for no length (the
//!    body goes to the end of the data).  A length written longer than
//!    needed is accepted.
//! 3. A partial length is accepted for a compressed packet (8) and a
//!    literal packet (11) only; the body is then several pieces (`body` and
//!    `more`), and the first piece is not required to be 512 bytes.
//! 4. The parser consumes exactly its input or refuses it: the pieces of the
//!    bodies lie inside the input, in order, each after a header of at least
//!    a byte and after the piece before it, they hold at most the input
//!    between them, and the last one ends at the end of the input.  A
//!    trailing byte that does not begin a packet, or begins one that is cut,
//!    refuses everything: no trailing garbage is ignored.
//! 5. At most `MAX_PACKETS` pieces of bodies, which are the packets when no
//!    partial length is used: a piece after them is refused as soon as there
//!    is a byte after them.
//!
//! The signature packet (RFC 4880, 5.2.3; `signature`):
//!
//! 6. Only version 4 is read; any other version is refused, a v3 packet
//!    included.
//! 7. The creation time, the expiry, the expiry of the key and the key
//!    flags are taken from the HASHED area only.  The unhashed area is not
//!    covered by the signature: anybody can append subpackets to it
//!    without breaking the signature, so what it says is of no weight, and
//!    a time subpacket there is not even looked at (its size is not
//!    checked).  Of what is in the hashed area, the last subpacket of a
//!    kind counts, and key flags of no byte are the flags 0: nothing is
//!    allowed (not "no flags", which the shell takes for any use).
//! 8. An unknown critical subpacket in the hashed area refuses the
//!    signature.  Known are the ones read here and the ones of RFC 4880 and
//!    RFC 9580 that say nothing a verifier of simple signing needs (see
//!    `known`); that includes policy URIs, which are not acted on.  A
//!    critical notation is refused, as no notation is understood here (the
//!    rule of go-crypto, which containers/image uses, for the signatures
//!    of a message and of its key); a notation without the bit is a note.
//!    In the unhashed area the critical bit means nothing.
//! 9. The issuer (key ID or fingerprint) and the embedded signatures are
//!    read from either area, and are only hints: the issuer is a guess of
//!    which key to try first (gpg writes it in the unhashed area); the
//!    shell tries every key whatever it says, so no decision depends on it.
//!    The embedded signature (a subkey's back-signature) is verified by the
//!    shell against the subkey like any other signature.
//! 10. A subpacket has a length of at least one (its kind) and lies inside
//!     its area; the areas lie inside the packet; the values of the
//!     signature follow the unhashed area, are as many as the algorithm
//!     wants, and what follows them in the packet is not looked at (it is
//!     not hashed: a signature can be padded and still verify).
//!
//! DER (`der`):
//!
//! 11. An element has a one octet tag, and a definite length: short, or long
//!     with 1 to 4 octets.  The indefinite form (0x80), a long form of more
//!     than 4 octets, and a length past the end are refused; a long form
//!     that is not minimal is accepted.  A sequence is read as the elements
//!     that fill it exactly; what follows the element is not looked at.
//!
//! The code is plain loops over slices with indices and flags, so that Aeneas
//! can translate it (tools/verify).  That the four readers return for every
//! input, and what they accept (the layout of the packets, of the signature
//! and of the DER elements; the times and the key flags of the hashed area
//! only; no unknown critical subpacket in it) is proved in Lean
//! (tools/verify/sigparse-core; its Spec.lean says what, and what not).

mod packet;
mod sig;
#[cfg(test)]
mod tests;

pub mod der;

pub use packet::{packets, Packet, MAX_PACKETS};
pub use sig::{signature, Signature, Subpackets};

/// A part of the input: `len` bytes from `off`.  The ones this crate returns
/// lie inside the input they are of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub off: usize,
    pub len: usize,
}

impl Span {
    /// Where it ends.
    pub fn end(&self) -> usize {
        self.off + self.len
    }

    /// Its bytes, of the input it is a span of.
    pub fn of<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.off..self.off + self.len]
    }
}

/// Why OpenPGP data is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A length past the end of the data, or data that ends in the middle
    /// of a field.
    Truncated,
    /// A byte where a packet begins has no top bit.
    NotAPacket,
    /// More than `MAX_PACKETS` packets, or pieces of bodies.
    TooManyPackets,
    /// A partial length for a packet that cannot have one.
    PartialLength,
    /// A signature of a version other than 4.
    Version(u8),
    /// A subpacket of length 0.
    EmptySubpacket,
    /// A time subpacket of the hashed area that is not 4 bytes.
    BadTime,
    /// An unknown subpacket of this kind (without the critical bit) with
    /// the critical bit, in the hashed area.
    UnknownCritical(u8),
    /// A signature algorithm that has no values to read.
    Algorithm(u8),
}

/// The `n` bytes at `at` as a big endian number.
fn be(data: &[u8], at: usize, n: usize) -> Result<usize, Error> {
    if at > data.len() || n > data.len() - at {
        return Err(Error::Truncated);
    }
    let mut v = 0usize;
    let mut i = 0;
    while i < n {
        v = (v << 8) | usize::from(data[at + i]);
        i += 1;
    }
    Ok(v)
}

/// The `len` bytes at `at`.
fn take(data: &[u8], at: usize, len: usize) -> Result<Span, Error> {
    if at > data.len() || len > data.len() - at {
        return Err(Error::Truncated);
    }
    Ok(Span { off: at, len })
}
