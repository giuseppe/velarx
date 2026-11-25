// SPDX-License-Identifier: Apache-2.0
//! Which addresses are local.  A registry may name a token realm, a
//! redirect or a CDN; none of them may lead to this machine, a private
//! network or the metadata service of a cloud (unless the registry is on
//! one itself, or the user said so).  The shell gives the bytes of an
//! address, the answer says whether it is local; where the addresses come
//! from and what is done with the answer is the shell's.
//!
//! The rules, for every address (see `rules`):
//!
//! 1. Nothing panics, whatever the bytes.
//! 2. An IPv4 address is local exactly when it is in one of the prefixes
//!    of `LOCAL_V4`.
//! 3. An IPv6 address is local exactly when it is in one of the prefixes
//!    of `LOCAL_V6`, or it embeds an IPv4 address (the forms of
//!    `EMBEDDED`: compatible, mapped, translated, NAT64, 6to4) that is local.
//! 4. So an address that embeds an IPv4 one is local exactly when the
//!    IPv4 one is, in both directions.
//!
//! Written to be translated (tools/verify): plain integers and arrays,
//! index loops, no closure, no iterator adapter, no library call.

/// The IPv4 addresses that are local, as (first address, length of the
/// prefix).
const LOCAL_V4: [(u32, u32); 15] = [
    (0x0000_0000, 8),  // 0.0.0.0/8: this network, the unspecified address
    (0x0a00_0000, 8),  // 10.0.0.0/8: private
    (0x6440_0000, 10), // 100.64.0.0/10: shared address space
    (0x7f00_0000, 8),  // 127.0.0.0/8: loopback
    (0xa9fe_0000, 16), // 169.254.0.0/16: link-local, the metadata services
    (0xac10_0000, 12), // 172.16.0.0/12: private
    (0xc0a8_0000, 16), // 192.168.0.0/16: private
    (0xc000_0000, 24), // 192.0.0.0/24: protocol assignments
    (0xc000_0200, 24), // 192.0.2.0/24: documentation
    (0xc612_0000, 15), // 198.18.0.0/15: benchmarking
    (0xc633_6400, 24), // 198.51.100.0/24: documentation
    (0xcb00_7100, 24), // 203.0.113.0/24: documentation
    // 168.63.129.16: a public address that Azure uses for a service of the
    // host (the wire server, which hands out the credentials of the machine):
    // a known target of request forgery
    (0xa83f_8110, 32),
    (0xe000_0000, 4), // 224.0.0.0/4: multicast
    (0xf000_0000, 4), // 240.0.0.0/4: reserved, and the broadcast address
];

/// The IPv6 addresses that are local, as (first address, length of the
/// prefix).
const LOCAL_V6: [(u128, u32); 11] = [
    (0x0000_0000_0000_0000_0000_0000_0000_0000, 128), // ::  unspecified
    (0x0000_0000_0000_0000_0000_0000_0000_0001, 128), // ::1 loopback
    (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),   // fc00::/7: unique local
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10),  // fe80::/10: link-local
    (0xfec0_0000_0000_0000_0000_0000_0000_0000, 10),  // fec0::/10: site-local, deprecated
    (0xff00_0000_0000_0000_0000_0000_0000_0000, 8),   // ff00::/8: multicast
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),  // 100::/64: discard-only
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 32),  // 2001::/32: Teredo
    (0x2001_0002_0000_0000_0000_0000_0000_0000, 48),  // 2001:2::/48: benchmarking
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),  // 2001:db8::/32: documentation
    (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),  // 64:ff9b:1::/48: NAT64, local use
];

/// The IPv6 prefixes that embed an IPv4 address, as (first address,
/// length of the prefix, how many bits the IPv4 address is shifted left
/// of the end of the address).  A name that resolves to one of them is
/// translated or tunnelled to the IPv4 address, wherever the network
/// does that.
const EMBEDDED: [(u128, u32, u32); 5] = [
    (0x0000_0000_0000_0000_0000_0000_0000_0000, 96, 0), // ::a.b.c.d: compatible
    (0x0000_0000_0000_0000_0000_ffff_0000_0000, 96, 0), // ::ffff:0:0/96: mapped
    (0x0000_0000_0000_0000_ffff_0000_0000_0000, 96, 0), // ::ffff:0:0:0/96: translated (SIIT)
    (0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96, 0), // 64:ff9b::/96: NAT64
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16, 80), // 2002::/16: 6to4
];

fn v4_number(a: [u8; 4]) -> u32 {
    let mut n = 0u32;
    let mut i = 0;
    while i < 4 {
        n = (n << 8) | a[i] as u32;
        i += 1;
    }
    n
}

fn v6_number(a: [u8; 16]) -> u128 {
    let mut n = 0u128;
    let mut i = 0;
    while i < 16 {
        n = (n << 8) | a[i] as u128;
        i += 1;
    }
    n
}

/// Whether the IPv4 address `a` is local.
pub fn local_v4(a: [u8; 4]) -> bool {
    local_number_v4(v4_number(a))
}

fn local_number_v4(a: u32) -> bool {
    let mut i = 0;
    while i < LOCAL_V4.len() {
        let (first, len) = LOCAL_V4[i];
        if (a ^ first) >> (32 - len) == 0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether the IPv6 address `a` is local, or embeds a local IPv4 one.
pub fn local_v6(a: [u8; 16]) -> bool {
    let n = v6_number(a);
    in_local_v6(n) || embeds_local_v4(n)
}

// One loop to a function: the translator does not take a `return` of a loop
// that is followed by another loop.
fn in_local_v6(n: u128) -> bool {
    let mut i = 0;
    while i < LOCAL_V6.len() {
        let (first, len) = LOCAL_V6[i];
        if (n ^ first) >> (128 - len) == 0 {
            return true;
        }
        i += 1;
    }
    false
}

fn embeds_local_v4(n: u128) -> bool {
    let mut i = 0;
    while i < EMBEDDED.len() {
        let (first, len, shift) = EMBEDDED[i];
        if (n ^ first) >> (128 - len) == 0 {
            return local_number_v4((n >> shift) as u32);
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
