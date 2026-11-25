// SPDX-License-Identifier: Apache-2.0
//! The names and the devices of small worlds, every one of them, and the
//! rules checked on each answer (see `rules`): every name of up to three
//! components of the namespaces and `overlay` and the words next to them,
//! with and without a final dot; every string of up to six bytes over an
//! alphabet of the bytes that matter; the names of the real attributes; and
//! every device of the numbers at the edges of each field, squared.

use super::rules::{verify_device, verify_name, verify_rdev};
use super::*;

const WORDS: [&str; 8] = [
    "trusted", "user", "security", "system", "overlay", "selinux", "x", "",
];

/// Every name of up to `left` more components, joined by dots, with and
/// without a dot at the end: how many.
fn components(prefix: &str, left: usize, n: &mut u64) {
    for word in WORDS {
        let name = if prefix.is_empty() {
            word.to_string()
        } else {
            format!("{prefix}.{word}")
        };
        for end in [name.clone(), format!("{name}.")] {
            verify_name(end.as_bytes());
            *n += 1;
        }
        if left > 1 {
            components(&name, left - 1, n);
        }
    }
}

#[test]
fn every_name_of_three_components() {
    let mut n = 0;
    components("", 3, &mut n);
    assert_eq!(n, 2 * (8 + 64 + 512));
}

#[test]
fn every_short_string_of_the_bytes_that_matter() {
    let alphabet = b".ut\0o";
    let mut n = 0u64;
    let mut names: Vec<Vec<u8>> = vec![Vec::new()];
    for _ in 0..7 {
        for name in &names {
            verify_name(name);
            n += 1;
        }
        names = names
            .iter()
            .flat_map(|s| {
                alphabet.iter().map(move |b| {
                    let mut t = s.clone();
                    t.push(*b);
                    t
                })
            })
            .collect();
    }
    assert_eq!(n, 1 + 5 + 25 + 125 + 625 + 3125 + 15625);
}

/// The names of the attributes that images have, and those that the
/// overlay reads, in every namespace and escaped as the kernel escapes
/// them.
#[test]
fn the_names_of_the_real_attributes() {
    for (name, want) in [
        ("security.capability", Class::Plain),
        ("security.selinux", Class::Label),
        ("security.selinuxx", Class::Plain),
        ("security.ima", Class::Plain),
        ("system.posix_acl_access", Class::Plain),
        ("system.posix_acl_default", Class::Plain),
        ("user.xdg.origin.url", Class::Plain),
        ("user.overlay", Class::Plain),
        ("trusted.overlay", Class::Plain),
        ("overlay.redirect", Class::Plain),
        ("trusted.overlay.redirect", Class::Overlay),
        ("trusted.overlay.metacopy", Class::Overlay),
        ("trusted.overlay.opaque", Class::Overlay),
        ("trusted.overlay.origin", Class::Overlay),
        ("trusted.overlay.overlay.opaque", Class::Overlay),
        ("trusted.overlay.", Class::Overlay),
        ("user.overlay.redirect", Class::Overlay),
        ("user.overlay.overlay.redirect", Class::Overlay),
        ("security.overlay.redirect", Class::Overlay),
        ("system.overlay.redirect", Class::Overlay),
        ("", Class::Refused(Refusal::Empty)),
        ("user.", Class::Refused(Refusal::NoName)),
        ("trusted.", Class::Refused(Refusal::NoName)),
        ("security.", Class::Refused(Refusal::NoName)),
        ("system.", Class::Refused(Refusal::NoName)),
        ("user.a\0b", Class::Refused(Refusal::Nul)),
    ] {
        assert_eq!(class(name.as_bytes()), want, "{name:?}");
        verify_name(name.as_bytes());
    }
}

const EDGES: [u32; 12] = [
    0,
    1,
    255,
    256,
    4095,
    4096,
    1 << 19,
    (1 << 20) - 1,
    1 << 20,
    (1 << 21) - 1,
    1 << 31,
    u32::MAX,
];

#[test]
fn every_pair_of_the_edges_of_the_numbers() {
    for major in EDGES {
        for minor in EDGES {
            verify_device(major, minor);
        }
    }
}

#[test]
fn every_major_and_every_minor_of_their_fields() {
    for major in 0..=4097 {
        for minor in [0, 1, 255, 256, 65535, 65536, (1 << 20) - 1, 1 << 20] {
            verify_device(major, minor);
        }
    }
    for minor in 0..=(1 << 20) + 1 {
        verify_device(0, minor);
        verify_device(4095, minor);
    }
}

#[test]
fn the_numbers_of_the_image_decode_to_numbers_that_fit() {
    for r in EDGES {
        verify_rdev(r);
    }
    for r in (0..=u32::MAX).step_by(4099) {
        verify_rdev(r);
    }
}

/// The device 0:0 has the number of the whiteout, and the numbers that do
/// not fit have none.
#[test]
fn the_number_of_the_whiteout_and_of_the_edges() {
    assert_eq!(rdev(0, 0), Some(WHITEOUT));
    assert_eq!(rdev(4096, 0), None);
    assert_eq!(rdev(0, 1 << 20), None);
    assert_eq!(rdev(1, 3), Some(0x103));
    assert_eq!(rdev(4095, (1 << 20) - 1), Some(u32::MAX));
}
