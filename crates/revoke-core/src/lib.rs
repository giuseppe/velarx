// SPDX-License-Identifier: Apache-2.0
//! Which revocation lists a node adopts.  A revoked peer wants to stay
//! admitted, and the lists reach a node in texts that other peers relay, a
//! relayer that may be hostile: what the node adopts must not depend on what
//! else the text holds.
//!
//! A list is signed by the authority that issued it and has a number; of
//! the lists of an issuer the node holds the one of the highest number, which
//! replaces the older (the list of the authority says every peer revoked so
//! far: whether a newer one may drop a peer is the authority's act, signed,
//! and not checked here).  The shell reads a text in parts, one per list,
//! checks the signature of each part, and gives each as a [`Part`], with
//! `verified` set only for a signature of an authority of the node.  The
//! issuer is a number the shell gives each of its authorities.
//!
//! The rules, for every state held and every parts:
//!
//! 1. Nothing panics, whatever the numbers (`u64::MAX` too).
//! 2. A part that is not verified never changes anything: [`adopt`] answers
//!    as it does when the part is not there.  A text of junk, forged
//!    parts or parts of other issuers hides no list that is valid.
//! 3. The number held of an issuer never decreases, and a list whose
//!    number is not higher than the one held (equal included) is not adopted.
//! 4. Of the verified parts of an issuer that are newer than the one held,
//!    the highest is adopted, and one only: an issuer is adopted at most once
//!    (of equal numbers, the first: two lists of one number are one list
//!    unless the authority signed two, which it should not).
//! 5. Adopting again what was adopted changes nothing, and the order of the
//!    parts does not change what is held after (that of two lists of one
//!    number apart).
//!
//! Written to be translated (tools/verify): plain structs, index loops with
//! flags, no closure, no iterator adapter.  The work is quadratic in the
//! parts: the shell hands over few (it bounds the signatures it checks).

/// The number of the list held of an issuer.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub struct Held {
    pub issuer: u64,
    pub number: u64,
}

/// A part of a text, as the shell judged it: the issuer and the number it
/// says, and whether its signature is one of an authority of the node.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub struct Part {
    pub issuer: u64,
    pub number: u64,
    pub verified: bool,
}

/// Whether a list of `issuer` of the number `number` is newer than what is
/// held (no list of the issuer held: it is).  The shell asks it before it
/// checks a signature that could change nothing.
pub fn newer(held: &[Held], issuer: u64, number: u64) -> bool {
    let mut newer = true;
    let mut i = 0;
    while i < held.len() && newer {
        if held[i].issuer == issuer && held[i].number >= number {
            newer = false;
        }
        i += 1;
    }
    newer
}

/// The parts (by their place in `parts`) to adopt: the highest verified one
/// of each issuer that is newer than the one held.
pub fn adopt(held: &[Held], parts: &[Part]) -> Vec<usize> {
    let mut adopted = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        let mut best = parts[i].verified && newer(held, parts[i].issuer, parts[i].number);
        let mut j = 0;
        while j < parts.len() && best {
            let beaten = parts[j].verified
                && parts[j].issuer == parts[i].issuer
                && (parts[j].number > parts[i].number
                    || (parts[j].number == parts[i].number && j < i));
            best = !beaten;
            j += 1;
        }
        if best {
            adopted.push(i);
        }
        i += 1;
    }
    adopted
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
