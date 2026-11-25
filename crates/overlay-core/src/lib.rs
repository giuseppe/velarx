// SPDX-License-Identifier: Apache-2.0
//! What of an entry of a layer may reach the overlay file system mounted
//! over its image.  The entries of a layer come from a registry, a peer or a
//! table nobody vouched for, and the overlay obeys what it finds in the
//! layers below it: an extended attribute `trusted.overlay.redirect` makes
//! a lookup follow a path of the object store, `metacopy` makes a file of no
//! data take its data from another, `opaque` hides what is below, and a
//! character device 0:0 is a whiteout that hides a file of a lower layer.
//! So what an entry may name is decided here, once, on bytes and numbers,
//! for every way into an image: the tar of a registry, a table of contents
//! of either form, the layers of a peer, the diff of a container.
//!
//! The rules:
//!
//! 1. `class`, `rdev`, `major_minor` and `whiteout` return, whatever the
//!    bytes and the numbers.
//! 2. `class` says `Overlay` exactly for a name that begins with one of the
//!    namespaces `trusted.`, `user.`, `security.` or `system.` and then
//!    `overlay.` (the kernel reads the first two; the others are held back
//!    too, as a layer never has them).  Every name with a longer name
//!    before it, as `trusted.overlay.overlay.x` that the kernel writes for
//!    an attribute of a nested overlay, begins so as well.  So a `Plain`
//!    name never begins with `trusted.overlay.` or `user.overlay.`.
//! 3. `class` says `Label` for `security.selinux` and for no other name:
//!    the engine labels, the image does not.
//! 4. `class` refuses an empty name, a name with a NUL, and a namespace
//!    with nothing after it (`user.`): no file system has such an
//!    attribute, and the image has no name of length 0 for it.
//! 5. `rdev` is `Some` exactly when the major is below 4096 and the minor
//!    below 2^20, which is what fits the 32 bits of `new_encode_dev`.  And
//!    then `major_minor(rdev)` gives the numbers back.
//! 6. `rdev` is 0 only for a device 0:0, and a character device 0:0 encodes
//!    to `WHITEOUT`, the whiteout of the overlay.  An image may carry one
//!    (a layer tarred from an overlay upper dir has them): it hides the
//!    files of the layers below it, which a `.wh.` name could do as well.
//!    `whiteout` is true exactly for that device.
//!
//! The code is plain loops over bytes, so that Aeneas can translate it
//! (tools/verify): `while i < n && ok` over a flag, no `loop`, no return or
//! `?` in a loop, no closure, no iterator, no `String`.  Whether a refused
//! entry is dropped or an error, and the words of an error, are for the
//! callers: a registry layer drops what a table of contents refuses.

/// The namespaces of an extended attribute that the kernel names.
const TRUSTED: &[u8] = b"trusted.";
const USER: &[u8] = b"user.";
const SECURITY: &[u8] = b"security.";
const SYSTEM: &[u8] = b"system.";
/// What follows a namespace for an attribute of the overlay.
const OVERLAY: &[u8] = b"overlay.";
/// The label of the engine.
const LABEL: &[u8] = b"security.selinux";

/// The number of the character device that the overlay reads as a
/// whiteout.
pub const WHITEOUT: u32 = 0;

/// What an attribute of an entry is.
#[cfg_attr(test, derive(Debug, Clone, Copy, PartialEq, Eq))]
pub enum Class {
    /// One that a layer has: `user.x`, `security.capability`.
    Plain,
    /// One of the overlay: its name begins with a namespace and
    /// `overlay.`.
    Overlay,
    /// The SELinux label, `security.selinux`.
    Label,
    /// Not a name of an attribute.
    Refused(Refusal),
}

/// Why a name is not one.
#[cfg_attr(test, derive(Debug, Clone, Copy, PartialEq, Eq))]
pub enum Refusal {
    Empty,
    Nul,
    /// A namespace and nothing after it.
    NoName,
}

/// `s[at..]` begins with `lit`.
fn has_at(s: &[u8], at: usize, lit: &[u8]) -> bool {
    let mut ok = at <= s.len() && s.len() - at >= lit.len();
    let mut i = 0;
    while ok && i < lit.len() {
        ok = s[at + i] == lit[i];
        i += 1;
    }
    ok
}

/// The length of the namespace `name` begins with, or 0.
fn namespace(name: &[u8]) -> usize {
    if has_at(name, 0, TRUSTED) {
        TRUSTED.len()
    } else if has_at(name, 0, USER) {
        USER.len()
    } else if has_at(name, 0, SECURITY) {
        SECURITY.len()
    } else if has_at(name, 0, SYSTEM) {
        SYSTEM.len()
    } else {
        0
    }
}

/// Whether `name` has a NUL.
fn has_nul(name: &[u8]) -> bool {
    let mut found = false;
    let mut i = 0;
    while i < name.len() && !found {
        found = name[i] == 0;
        i += 1;
    }
    found
}

/// What the attribute `name` of an entry is.
pub fn class(name: &[u8]) -> Class {
    let ns = namespace(name);
    if name.is_empty() {
        Class::Refused(Refusal::Empty)
    } else if has_nul(name) {
        Class::Refused(Refusal::Nul)
    } else if ns == name.len() {
        Class::Refused(Refusal::NoName)
    } else if has_at(name, ns, OVERLAY) && ns > 0 {
        Class::Overlay
    } else if name.len() == LABEL.len() && has_at(name, 0, LABEL) {
        Class::Label
    } else {
        Class::Plain
    }
}

/// The number `new_encode_dev` of the kernel makes of a device, which the
/// image keeps as its `rdev`: the low 8 bits of the minor, the major, and
/// the other 12 bits of the minor over them.  None when the numbers do not
/// fit (a major of 4096 or more, a minor of 2^20 or more).
pub fn rdev(major: u32, minor: u32) -> Option<u32> {
    if major < 1 << 12 && minor < 1 << 20 {
        Some((minor & 0xff) | (major << 8) | ((minor & 0xfff00) << 12))
    } else {
        None
    }
}

/// The major and the minor of an `rdev` (`new_decode_dev`).
pub fn major_minor(rdev: u32) -> (u32, u32) {
    (
        (rdev >> 8) & 0xfff,
        (rdev & 0xff) | ((rdev >> 12) & 0xfff00),
    )
}

/// Whether a device is the whiteout of the overlay: a character device
/// 0:0.
pub fn whiteout(is_char: bool, major: u32, minor: u32) -> bool {
    is_char && major == 0 && minor == 0
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
