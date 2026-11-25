// SPDX-License-Identifier: Apache-2.0
//! The addresses of the edges, and the rules checked on each answer (see
//! `rules`): the IPv4 addresses of every /16 (so every /8 boundary and
//! every boundary of a prefix of at most 16 bits, with a few low bytes),
//! the first and the last address of every prefix and their neighbours, and
//! for IPv6 the same, with every embedding of every IPv4 edge.

use super::rules::*;
use super::*;

/// The bits a prefix of `len` bits leaves free.
fn host_bits_32(len: usize) -> u32 {
    u32::MAX.checked_shr(len as u32).unwrap_or(0)
}

fn host_bits_128(len: usize) -> u128 {
    u128::MAX.checked_shr(len as u32).unwrap_or(0)
}

/// The first, the last, the one before and the one after of every IPv4
/// prefix.
fn v4_edges() -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    for (p, len) in local_v4_prefixes() {
        let first = u32::from_be_bytes(p);
        let last = first | host_bits_32(len);
        out.extend([first, last, first.wrapping_sub(1), last.wrapping_add(1)]);
    }
    out.into_iter().map(u32::to_be_bytes).collect()
}

fn v6_edges() -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    let all = local_v6_prefixes()
        .into_iter()
        .chain(embedded_prefixes().into_iter().map(|(p, len, _)| (p, len)));
    for (p, len) in all {
        let first = u128::from_be_bytes(p);
        let last = first | host_bits_128(len);
        out.extend([first, last, first.wrapping_sub(1), last.wrapping_add(1)]);
    }
    out.into_iter().map(u128::to_be_bytes).collect()
}

#[test]
fn every_v4_address_of_a_16_is_as_stated() {
    for hi in 0..=255u8 {
        for lo in 0..=255u8 {
            for (c, d) in [(0, 0), (0, 255), (1, 0), (128, 7), (255, 254), (255, 255)] {
                let a = [hi, lo, c, d];
                assert_eq!(local_v4(a), local_v4_ref(a), "{a:?}");
            }
        }
    }
}

#[test]
fn the_edges_of_every_v4_prefix() {
    for (p, len) in local_v4_prefixes() {
        let first = u32::from_be_bytes(p);
        let last = first | host_bits_32(len);
        assert!(local_v4(first.to_be_bytes()) && local_v4(last.to_be_bytes()));
    }
    for a in v4_edges() {
        assert_eq!(local_v4(a), local_v4_ref(a), "{a:?}");
    }
}

#[test]
fn the_edges_of_every_v6_prefix() {
    for (p, len) in local_v6_prefixes() {
        let first = u128::from_be_bytes(p);
        let last = first | host_bits_128(len);
        assert!(local_v6(first.to_be_bytes()) && local_v6(last.to_be_bytes()));
    }
    for a in v6_edges() {
        assert_eq!(local_v6(a), local_v6_ref(a), "{a:x?}");
    }
}

#[test]
fn an_address_that_embeds_an_ipv4_one_is_local_when_it_is() {
    let mut v4 = v4_edges();
    v4.extend([[8, 8, 8, 8], [1, 1, 1, 1], [127, 0, 0, 1]]);
    for (prefix, len, at) in embedded_prefixes() {
        for a in &v4 {
            for fill in [0x00, 0xff] {
                let e = embed(prefix, len, at, *a, fill);
                assert_eq!(local_v6(e), local_v4(*a), "{e:x?} embeds {a:?}");
                assert_eq!(local_v6(e), local_v6_ref(e), "{e:x?}");
            }
        }
    }
}

#[test]
fn nothing_panics() {
    for hi in 0..=255u8 {
        local_v4([hi; 4]);
        local_v6([hi; 16]);
    }
}
