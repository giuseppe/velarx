// SPDX-License-Identifier: Apache-2.0
//! Facts about the host names of registries.

use std::net::IpAddr;

/// The host of `host[:port]` as written in a reference or in a URL: a name,
/// an IPv4 address, or an IPv6 address in brackets (or bare, without a port).
fn bare_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((host, "")) => host,
            Some((host, port)) if port.starts_with(':') => host,
            // (not an address in brackets)
            _ => authority,
        };
    }
    // (a bare IPv6 address has colons of its own and no port)
    if authority.parse::<IpAddr>().is_ok() {
        return authority;
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

/// Whether `authority` (`host[:port]`, the first component of an image
/// reference) names this machine's loopback: `localhost`, or an address
/// that is one (`127.0.0.0/8`, `::1`, the IPv4 ones mapped in IPv6).  The
/// host is parsed, not matched by its prefix: `127.example.com` and
/// `localhost.example.com` are other machines.
pub fn is_loopback_host(authority: &str) -> bool {
    let host = bare_host(authority);
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical().is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loopback_is_localhost_and_the_addresses_of_it() {
        for yes in [
            "localhost",
            "localhost:5000",
            "LocalHost:5000",
            "127.0.0.1",
            "127.0.0.1:5000",
            "127.1.2.3:80",
            "[::1]",
            "[::1]:5000",
            "::1",
            "[::ffff:127.0.0.1]:5000",
        ] {
            assert!(is_loopback_host(yes), "{yes}");
        }
    }

    #[test]
    fn other_hosts_are_not_the_loopback() {
        for no in [
            "127.evil.example",
            "127.evil.example:5000",
            "localhost.example.com",
            "localhost.evil:5000",
            "[::1].example",
            "128.0.0.1",
            "10.0.0.1:5000",
            "[::2]:5000",
            "docker.io",
            "",
        ] {
            assert!(!is_loopback_host(no), "{no}");
        }
    }
}
