// SPDX-License-Identifier: Apache-2.0
//! The rules of the entries, stated on what the kernel and the image
//! format say and not on how `class` and `rdev` walk the bytes: a name is
//! the overlay's when it is a namespace, `overlay.` and anything, and a
//! device is the kernel's `new_encode_dev` of two numbers that fit it.

use super::*;

const NAMESPACES: [&[u8]; 4] = [b"trusted.", b"user.", b"security.", b"system."];

/// Whether `name` is a namespace, `overlay.` and anything after it.
fn is_overlay(name: &[u8]) -> bool {
    NAMESPACES
        .iter()
        .any(|ns| name.starts_with(ns) && name[ns.len()..].starts_with(b"overlay."))
}

/// The statements of a name.
pub(crate) fn verify_name(name: &[u8]) {
    let c = class(name);
    let no_name = NAMESPACES.contains(&name);
    let refused = name.is_empty() || name.contains(&0) || no_name;
    let shown = String::from_utf8_lossy(name);
    assert_eq!(matches!(c, Class::Refused(_)), refused, "{shown:?}");
    if refused {
        let why = if name.is_empty() {
            Refusal::Empty
        } else if name.contains(&0) {
            Refusal::Nul
        } else {
            Refusal::NoName
        };
        assert_eq!(c, Class::Refused(why), "{shown:?}");
        return;
    }
    assert_eq!(c == Class::Overlay, is_overlay(name), "{shown:?}");
    assert_eq!(
        c == Class::Label,
        name == b"security.selinux" && !is_overlay(name),
        "{shown:?}"
    );
    if c == Class::Plain {
        // what the kernel reads of a layer is never a plain name
        assert!(!name.starts_with(b"trusted.overlay."), "{shown:?}");
        assert!(!name.starts_with(b"user.overlay."), "{shown:?}");
    }
}

/// The statements of a device of each kind.
pub(crate) fn verify_device(major: u32, minor: u32) {
    for is_char in [true, false] {
        let at = format!("{major}:{minor} char={is_char}");
        let zero = major == 0 && minor == 0;
        let fits = u64::from(major) < 4096 && u64::from(minor) < 1 << 20;
        assert_eq!(whiteout(is_char, major, minor), is_char && zero, "{at}");
        let r = rdev(major, minor);
        assert_eq!(r.is_some(), fits, "{at}");
        let Some(r) = r else { continue };
        // the kernel: the minor in 8 bits, then the major, then the rest
        // of the minor
        let want = u64::from(minor & 0xff) | u64::from(major) << 8 | u64::from(minor >> 8) << 20;
        assert_eq!(u64::from(r), want, "{at}");
        assert_eq!(major_minor(r), (major, minor), "{at}");
        assert_eq!(r == WHITEOUT, zero, "{at}");
    }
}

/// The statements of a number of the image: it is the device of numbers
/// that fit, and no other number is.
pub(crate) fn verify_rdev(r: u32) {
    let (major, minor) = major_minor(r);
    assert!(major < 4096 && minor < 1 << 20, "{r}");
    assert_eq!(rdev(major, minor), Some(r), "{r}");
}
