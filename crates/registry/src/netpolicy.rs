// SPDX-License-Identifier: Apache-2.0
//! Where a registry may send the client: a token realm, a redirect and the
//! hosts they name must not lead to this machine or to a private network,
//! unless the registry is itself on one (or `allow-private-addresses` is set
//! for it in `registries.conf`).  The names are checked when the connection
//! is made, on the addresses that are connected to, so that a name that
//! changes its answer cannot get round the check.

use std::net::{IpAddr, SocketAddr};

/// Whether `host` names this machine or a private network (an address of
/// the table of `velarx_addr_core`, or `localhost`).
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

/// Whether `ip` is local (see `velarx_addr_core`): of this machine, of a
/// private network or of a metadata service of a cloud.
pub(crate) fn local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => velarx_addr_core::local_v4(a.octets()),
        IpAddr::V6(a) => velarx_addr_core::local_v6(a.octets()),
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
                 (`allow-private-addresses = true` in the block of registries.conf of \
                 the registry, or of the registry it is a mirror of, allows it)",
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
                     is not on one (`allow-private-addresses = true` in the block of registries.conf \
                     of the registry, or of the registry it is a mirror of, allows it)",
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

    /// What `local_ip` answers for addresses that are not plainly public or
    /// private: the ones that lead to a local IPv4 address, or are not
    /// public unicast addresses, are local too.
    #[test]
    fn the_odd_addresses_are_told_apart() {
        let rows = [
            // (address, answered local)
            ("::ffff:169.254.169.254", true),
            ("::ffff:8.8.8.8", false),
            // the translated form
            ("::ffff:0:a9fe:a9fe", true),
            ("::ffff:0:808:808", false),
            // NAT64 of the metadata address
            ("64:ff9b::a9fe:a9fe", true),
            // NAT64 of the loopback
            ("64:ff9b::7f00:1", true),
            ("64:ff9b::808:808", false),
            // 6to4 of the metadata address
            ("2002:a9fe:a9fe::1", true),
            // 6to4 of a private address
            ("2002:0a00:0001::1", true),
            ("2002:0808:0808::1", false),
            // IPv4-compatible metadata address
            ("::169.254.169.254", true),
            // IPv4-compatible private address
            ("::10.0.0.1", true),
            ("::8.8.8.8", false),
            // site-local
            ("fec0::1", true),
            // multicast, v6
            ("ff02::1", true),
            // multicast, v4
            ("224.0.0.1", true),
            // reserved, v4
            ("240.0.0.1", true),
            ("255.255.255.255", true),
            ("0.0.0.0", true),
            ("::", true),
            // special-purpose block
            ("192.0.0.8", true),
            // benchmarking
            ("198.18.0.1", true),
            // Teredo
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", true),
            // NAT64 local-use prefix
            ("64:ff9b:1::1", true),
            ("100.64.0.1", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("172.32.0.1", false),
            ("fd00::1", true),
            ("fe80::1", true),
            ("2606:4700::1111", false),
            ("192.0.1.1", false),
            ("192.0.2.1", true),
            ("198.51.100.7", true),
            ("203.0.113.9", true),
            ("168.63.129.16", true),
            ("168.63.129.17", false),
            ("100::1", true),
            ("2001:2::1", true),
            ("2001:db8::1", true),
            ("2001:3::1", false),
            ("198.20.0.1", false),
            ("223.255.255.255", false),
            ("2001:4860::8888", false),
            ("fbff::1", false),
        ];
        for (a, answered) in rows {
            assert_eq!(local_ip(a.parse().unwrap()), answered, "{a}");
        }
    }
}
