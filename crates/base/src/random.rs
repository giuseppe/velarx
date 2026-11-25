// SPDX-License-Identifier: Apache-2.0
//! Random bytes of the kernel's pool: the names of holds, staging
//! directories, scopes and allocations, that must differ from every other
//! and say nothing, and the keys that seal what a checkpoint share carries.

use std::fmt::Write as _;

/// Fill `bytes` from the kernel's pool.  A failure of `getrandom` ends the
/// process: nothing can name or seal anything without it.
pub fn fill(bytes: &mut [u8]) {
    let mut filled = 0;
    // (only a wait for the pool at boot can be interrupted)
    while filled < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("getrandom: {e}"),
        }
    }
}

/// 16 random bytes of the kernel's pool, laid out as a version 4 UUID (the
/// version and the variant bits set: 122 random bits).
fn uuid_v4() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A new random name: 32 lowercase hex digits.
pub fn token() -> String {
    hex(&uuid_v4())
}

/// A new random UUID in its usual text (`8-4-4-4-12` hex digits).
pub fn uuid() -> String {
    let b = uuid_v4();
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

/// 16 random bytes that name one thing and no other.
pub fn bytes16() -> [u8; 16] {
    uuid_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_32_hex_digits_and_never_repeats() {
        let a = token();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(a, token());
    }

    #[test]
    fn a_uuid_is_version_4_in_its_usual_text() {
        let u = uuid();
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(u, uuid());
    }
}
