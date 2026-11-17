// SPDX-License-Identifier: Apache-2.0
//! Where a registry may send the client: a token realm, a redirect and the
//! hosts they name must not lead to this machine or to a private network,
//! unless the registry is itself on one (or `allow-private-addresses` is set
//! for it in `registries.conf`).  The names are checked when the connection
//! is made, on the addresses that are connected to, so that a name that
//! changes its answer cannot get round the check.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Whether `host` names this machine or a private network (loopback,
/// RFC 1918, shared address space, link-local, unique local, `localhost`).
pub(crate) fn local_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) => local_ip(ip),
        Err(_) => {
            let d = host.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
    }
}

/// Whether `ip` is of this machine or of a private network, which includes
/// the addresses of the metadata services of the clouds (link-local,
/// shared address space, unique local).
pub(crate) fn local_ip(ip: IpAddr) -> bool {
    let v4 = |a: Ipv4Addr| {
        a.is_loopback()
            || a.is_private()
            || a.is_link_local()
            || a.is_unspecified()
            || a.is_broadcast()
            || a.octets()[0] == 0
            || (a.octets()[0] == 100 && a.octets()[1] & 0xc0 == 0x40)
    };
    match ip {
        IpAddr::V4(a) => v4(a),
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            a.is_loopback()
                || a.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || a.to_ipv4_mapped().is_some_and(v4)
        }
    }
}

/// The addresses of the name `host` (the system's resolver; tests name
/// their own).
pub(crate) async fn lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(test)]
    if let Some(addrs) = crate::client::hint_tests::dns(host) {
        return Ok(addrs);
    }
    tokio::net::lookup_host((host, port))
        .await
        .map(Iterator::collect)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                LookupError {
                    name: host.to_string(),
                    source: e,
                },
            )
        })
}

/// The system's resolver could not give the addresses of `name`.  Typed, so
/// that whoever reports a failed connection can tell it from the others.
#[derive(Debug)]
pub(crate) struct LookupError {
    pub name: String,
    source: std::io::Error,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot look up {}: {}", self.name, self.source)
    }
}

impl std::error::Error for LookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The rule of one registry.
pub struct Policy {
    /// The registry's host, without the port.
    registry: String,
    allow: bool,
    private: tokio::sync::OnceCell<bool>,
}

impl Policy {
    pub fn new(registry: &str, allow: bool) -> Self {
        let registry = reqwest::Url::parse(&format!("https://{registry}/"))
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_else(|| registry.to_ascii_lowercase());
        Self {
            registry,
            allow,
            private: tokio::sync::OnceCell::new(),
        }
    }

    /// Whether private addresses are allowed: the registry is on one (by
    /// its address or because its name resolves to one) or the user said so.
    async fn private_allowed(&self) -> bool {
        *self
            .private
            .get_or_init(|| async {
                if self.allow || local_host(&self.registry) {
                    return true;
                }
                let bare = self.registry.trim_start_matches('[').trim_end_matches(']');
                if bare.parse::<IpAddr>().is_ok() {
                    return false;
                }
                match lookup(bare, 443).await {
                    Ok(addrs) => {
                        let local = addrs.iter().any(|a| local_ip(a.ip()));
                        #[cfg(test)]
                        let local = local && !crate::client::hint_tests::pretend_public(bare);
                        local
                    }
                    Err(_) => false,
                }
            })
            .await
    }

    /// Refuse a URL whose host is a private address written out (a name is
    /// checked when it is resolved).
    pub async fn check_url(&self, url: &reqwest::Url) -> Result<(), String> {
        let Some(host) = url.host_str() else {
            return Err(format!("`{url}` has no host"));
        };
        let local = local_host(host);
        if local && !self.private_allowed().await {
            return Err(format!(
                "refusing {}: a private address, and the registry {} is not on one \
                 (`allow-private-addresses` in registries.conf allows it)",
                host, self.registry
            ));
        }
        Ok(())
    }

    /// The addresses of `name` that may be connected to.
    pub async fn filter(
        &self,
        name: &str,
        addrs: Vec<SocketAddr>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        if name == self.registry || self.private_allowed().await {
            return Ok(addrs);
        }
        let public: Vec<SocketAddr> = addrs
            .iter()
            .filter(|a| !local_ip(a.ip()))
            .copied()
            .collect();
        if public.is_empty() && !addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to connect to {name}: it is a private address, and the registry {} \
                     is not on one (`allow-private-addresses` in registries.conf allows it)",
                    self.registry
                ),
            ));
        }
        Ok(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_private_and_metadata_addresses_are_local() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "::1",
            "::ffff:10.0.0.1",
            "0.0.0.0",
        ] {
            assert!(local_ip(a.parse().unwrap()), "{a}");
        }
        for a in ["1.1.1.1", "8.8.8.8", "100.128.0.1", "2606:4700::1111"] {
            assert!(!local_ip(a.parse().unwrap()), "{a}");
        }
        assert!(local_host("localhost") && local_host("[::1]") && local_host("a.localhost."));
        assert!(!local_host("quay.io"));
    }
}
