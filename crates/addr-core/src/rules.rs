// SPDX-License-Identifier: Apache-2.0
//! The rules of the addresses (see the head of the crate), stated again,
//! independently of how `local_v4` and `local_v6` compute: the prefixes
//! are written as an address and a length, as in the registries of the
//! internet, and one matcher compares the bits of a byte string.

/// Whether the first `len` bits of `addr` are those of `prefix`.
pub fn in_prefix(addr: &[u8], prefix: &[u8], len: usize) -> bool {
    (0..len).all(|bit| {
        let mask = 0x80u8 >> (bit % 8);
        addr[bit / 8] & mask == prefix[bit / 8] & mask
    })
}

/// The segments of an IPv6 address, as its 16 bytes.
pub fn v6(segments: [u16; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, s) in segments.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&s.to_be_bytes());
    }
    out
}

/// The local IPv4 prefixes (RFC 6890: this network, private, shared,
/// loopback, link-local, protocol assignments, documentation, benchmarking,
/// multicast, reserved and broadcast, and the wire server of Azure).
pub fn local_v4_prefixes() -> Vec<([u8; 4], usize)> {
    vec![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([168, 63, 129, 16], 32),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
}

/// The local IPv6 prefixes.
pub fn local_v6_prefixes() -> Vec<([u8; 16], usize)> {
    vec![
        (v6([0, 0, 0, 0, 0, 0, 0, 0]), 128),
        (v6([0, 0, 0, 0, 0, 0, 0, 1]), 128),
        (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7),
        (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10),
        (v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10),
        (v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8),
        (v6([0x100, 0, 0, 0, 0, 0, 0, 0]), 64),
        (v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32),
        (v6([0x2001, 2, 0, 0, 0, 0, 0, 0]), 48),
        (v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32),
        (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48),
    ]
}

/// The IPv6 prefixes that embed an IPv4 address, with the offset of its
/// first byte.
pub fn embedded_prefixes() -> Vec<([u8; 16], usize, usize)> {
    vec![
        (v6([0, 0, 0, 0, 0, 0, 0, 0]), 96, 12),
        (v6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96, 12),
        (v6([0, 0, 0, 0, 0xffff, 0, 0, 0]), 96, 12),
        (v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96, 12),
        (v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16, 2),
    ]
}

/// The statement of `local_v4`.
pub fn local_v4_ref(a: [u8; 4]) -> bool {
    local_v4_prefixes()
        .iter()
        .any(|(p, len)| in_prefix(&a, p, *len))
}

/// The statement of `local_v6`: in a local prefix, or the embedded IPv4
/// address is local.
pub fn local_v6_ref(a: [u8; 16]) -> bool {
    local_v6_prefixes()
        .iter()
        .any(|(p, len)| in_prefix(&a, p, *len))
        || embedded_prefixes().iter().any(|(p, len, at)| {
            in_prefix(&a, p, *len) && local_v4_ref(a[*at..*at + 4].try_into().unwrap())
        })
}

/// The address of the prefix `prefix` of length `len`, with `v4` at `at`
/// and the bits the prefix does not fix set to `fill`.
pub fn embed(prefix: [u8; 16], len: usize, at: usize, v4: [u8; 4], fill: u8) -> [u8; 16] {
    let mut a = prefix;
    for bit in len..128 {
        let mask = 0x80u8 >> (bit % 8);
        a[bit / 8] = (a[bit / 8] & !mask) | (fill & mask);
    }
    a[at..at + 4].copy_from_slice(&v4);
    a
}
