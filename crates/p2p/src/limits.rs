// SPDX-License-Identifier: Apache-2.0
//! The sizes of the wire format, and the checks of what a peer names.

/// Digests in one chunk request.
pub const MAX_REQUEST_DIGESTS: usize = 256;

/// The largest chunk (or file) served to a peer.
pub const MAX_ITEM_BYTES: usize = velarx_storage::MAX_SERVED_BYTES;

/// Bytes of chunks in one response; the first chunk is served up to
/// [`MAX_ITEM_BYTES`] whatever the rest weighs.
pub const MAX_RESPONSE_PAYLOAD: usize = 16 * 1024 * 1024;
const _: () = assert!(MAX_ITEM_BYTES <= MAX_RESPONSE_PAYLOAD);

/// The largest message of the gossip on the wire, and of an answer to one.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// The largest revocation lists on the wire, in a handshake or in a gossip
/// message: the lists go whole, so that a revoked peer is never let in by a
/// node that was not told.  The bound only keeps a length field from asking
/// for more; the bytes are read as they come.
pub const MAX_LISTS_BYTES: usize = 1 << 30;

/// Whether `s` is a digest this node can name: the hash of content (sha256
/// or sha512), or the fs-verity digest of a file in either algorithm.
pub fn is_digest(s: &str) -> bool {
    velarx_types::digest::Digest::parse_key(s).is_ok()
}

/// Whether `data` is what the digest `want` names, in its kind and its
/// algorithm: the hash of the bytes for a content digest, their fs-verity
/// digest for an fs-verity one.  The other algorithm's digest of the same
/// bytes is no match.
pub fn names(want: &str, data: &[u8]) -> bool {
    velarx_types::digest::Digest::parse_key(want)
        .is_ok_and(|d| velarx_storage::digest_names(&d, data))
}

/// The start of a string from a peer for a log line: at most 20 bytes, cut
/// on a character boundary (slicing at 20 panics inside a multibyte one).
pub fn short(s: &str) -> &str {
    let mut end = s.len().min(20);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A name a container may have: letters, digits, `-`, `_` and `.`, at most
/// 253 bytes.
pub fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_never_cuts_a_character() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(&"a".repeat(30)), "a".repeat(20));
        // Byte 20 is inside the two-byte character.
        let s = format!("{}é{}", "a".repeat(19), "b".repeat(10));
        assert_eq!(short(&s), "a".repeat(19));
        let s = "é".repeat(30);
        assert_eq!(short(&s).len(), 20);
        assert_eq!(short(""), "");
    }

    #[test]
    fn test_dns_names() {
        assert!(valid_dns_name("web-1.cluster_a"));
        let label = "a".repeat(64);
        for bad in [
            "",
            "a b",
            "a/b",
            "é",
            "a\n",
            &"a".repeat(254),
            &label,
            "a..b",
        ] {
            assert!(!valid_dns_name(bad), "{bad:?}");
        }
    }
}
