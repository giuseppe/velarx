// SPDX-License-Identifier: Apache-2.0
//! What the names of images have in common in every crate: the rule that
//! tells a registry in a name, which is the one of the grammar of the
//! references (`velarx-ref-core`), and the parts of that grammar that are
//! for the shell: the words of an error, and one spelling of an address.

/// Whether the first component of an image name (the part before the first
/// `/`) is a registry: it has a dot or a port, or is `localhost` (the rule
/// of containers/image).
pub fn is_registry_domain(first: &str) -> bool {
    velarx_ref_core::looks_like_host(first.as_bytes())
}

/// An IPv6 host between brackets is written as the address prints, so that
/// an address has one spelling: `[::1]`, not `[0::1]` (which the grammar of
/// `velarx-ref-core` reads as a host as well).  Another host is as it is.
fn host_spelling_ok(host: &[u8]) -> bool {
    let Some(inner) = host.strip_prefix(b"[") else {
        return true;
    };
    let end = inner.iter().position(|b| *b == b']').unwrap_or(inner.len());
    let inner = &inner[..end];
    std::str::from_utf8(inner)
        .ok()
        .and_then(|text| text.parse::<std::net::Ipv6Addr>().ok())
        .is_some_and(|address| address.to_string().as_bytes() == inner)
}

/// Where the parts of the reference `s` are (`velarx_ref_core::parse`), or
/// what is wrong with it in words.
pub fn parse(s: &[u8]) -> Result<velarx_ref_core::Spans, String> {
    let spans = velarx_ref_core::parse(s).map_err(|e| describe(&e, s))?;
    if host_spelling_ok(&s[..spans.host_end]) {
        Ok(spans)
    } else {
        Err(format!("not a host: {}", spelling()))
    }
}

/// Whether `s` is a host, as `velarx_ref_core::host_ok`, with one spelling
/// of an IPv6 address.
pub fn host_ok(s: &[u8]) -> bool {
    velarx_ref_core::host_ok(s) && host_spelling_ok(s)
}

/// Whether `s` is a host or a host and a path, as
/// `velarx_ref_core::prefix_ok`, with one spelling of an IPv6 address.
pub fn prefix_ok(s: &[u8]) -> bool {
    let host = s.iter().position(|b| *b == b'/').unwrap_or(s.len());
    velarx_ref_core::prefix_ok(s) && host_spelling_ok(&s[..host])
}

/// Why `s` is not a host, in words.
pub fn why_not_a_host(s: &[u8]) -> String {
    match velarx_ref_core::host_error(s) {
        Err(e) => describe(&e, s),
        Ok(()) => spelling().to_string(),
    }
}

/// Why `s` is not a host, or a host and a path (what a prefix or a location
/// of registries.conf is), in words.
pub fn why_not_a_prefix(s: &[u8]) -> String {
    match velarx_ref_core::prefix_error(s) {
        Err(e) => describe(&e, s),
        Ok(()) => spelling().to_string(),
    }
}

fn spelling() -> &'static str {
    "an IPv6 address is written as it is printed"
}

/// What is wrong with `s`, in words, for the message of an error.
fn describe(e: &velarx_ref_core::Error, s: &[u8]) -> String {
    use velarx_ref_core::Error;
    let at = |i: usize| match s.get(i) {
        Some(b) => format!("byte {i} ({:?})", *b as char),
        None => format!("the end of it, after {i} bytes"),
    };
    let capital = |i: usize| s.get(i).is_some_and(|b| b.is_ascii_uppercase());
    match e {
        Error::Empty => "it is empty".to_string(),
        Error::TooLong => "it is too long".to_string(),
        Error::Id => "64 hex digits are an image id, not a name".to_string(),
        Error::Host(i) if capital(*i) => {
            format!("a host is written in lower case, at {}", at(*i))
        }
        Error::Host(i) => format!("not a host, at {}", at(*i)),
        Error::Path(i) if capital(*i) => {
            format!("a repository name is written in lower case, at {}", at(*i))
        }
        Error::Path(i) => format!("not a repository name, at {}", at(*i)),
        Error::Tag(i) => format!("not a tag, at {}", at(*i)),
        Error::Digest(i) => format!("not a digest, at {}", at(*i)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_component_is_a_registry_with_a_dot_a_port_or_localhost() {
        for yes in ["quay.io", "localhost", "localhost:5000", "host:5000", "a.b"] {
            assert!(is_registry_domain(yes), "{yes}");
        }
        for no in ["library", "alpine", "localhost2", "Localhost", "myorg", ""] {
            assert!(!is_registry_domain(no), "{no}");
        }
    }

    #[test]
    fn an_ipv6_host_has_one_spelling() {
        for yes in ["[::1]:5000/a", "[2001:db8::1]/a", "a.io/a"] {
            assert!(parse(yes.as_bytes()).is_ok(), "{yes}");
        }
        for no in [
            "[0::1]:5000/a",
            "[:]/a",
            "[0:0::1]/a",
            "[::01]/a",
            "[::1:]/a",
        ] {
            assert!(parse(no.as_bytes()).is_err(), "{no}");
        }
        assert!(host_ok(b"[::1]") && !host_ok(b"[0::1]"));
        assert!(prefix_ok(b"[::1]:5000/a") && !prefix_ok(b"[0::1]:5000/a"));
    }

    #[test]
    fn why_a_prefix_is_not_one() {
        assert!(why_not_a_prefix(b"Quay.io/a").contains("host is written in lower case, at byte 0"));
        assert!(why_not_a_prefix(b"quay.io/a/B").contains("lower case, at byte 10"));
        assert!(why_not_a_prefix(b"[0::1]").contains("IPv6"));
        let long = [b"a.io/".as_slice(), &[b'a'; 300]].concat();
        assert!(!why_not_a_prefix(&long).contains("too long"));
        assert!(why_not_a_host(b"a/b").contains("not a host, at byte 1"));
    }

    #[test]
    fn what_an_error_says() {
        for (s, said) in [
            (
                "Quay.IO/a",
                "a host is written in lower case, at byte 0 ('Q')",
            ),
            (
                "quay.io/A",
                "a repository name is written in lower case, at byte 8 ('A')",
            ),
            ("", "it is empty"),
        ] {
            assert_eq!(parse(s.as_bytes()).err().as_deref(), Some(said));
        }
    }
}
