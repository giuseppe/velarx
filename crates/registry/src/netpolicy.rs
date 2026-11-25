// SPDX-License-Identifier: Apache-2.0
//! Where a registry may send the client: a token realm, a redirect and the
//! hosts they name must not lead to this machine or to a private network,
//! unless the registry is itself on one (or `allow-private-addresses` is set
//! for it in `registries.conf`).  The names are checked when the connection
//! is made, on the addresses that are connected to, so that a name that
//! changes its answer cannot get round the check.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;

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

/// Where a process that cannot resolve names itself gets them (a confined
/// pull worker).
pub trait Resolver: Send + Sync {
    /// The addresses of the name `host`, each with `port`.
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> futures::future::BoxFuture<'a, std::io::Result<Vec<SocketAddr>>>;
}

static RESOLVER: std::sync::OnceLock<std::sync::Arc<dyn Resolver>> = std::sync::OnceLock::new();

/// Resolve the names of this process with `resolver` from now on, not with
/// the system's (once: a second call is refused).
pub fn use_resolver(resolver: std::sync::Arc<dyn Resolver>) -> Result<(), &'static str> {
    RESOLVER
        .set(resolver)
        .map_err(|_| "the names of this process have a resolver already")
}

/// The addresses of the name `host` (the resolver of the process if it has
/// one, else the system's; tests name their own).
pub(crate) async fn lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(test)]
    if let Some(addrs) = crate::client::hint_tests::dns(host) {
        return Ok(addrs);
    }
    let found = match RESOLVER.get() {
        Some(resolver) => resolver.lookup(host, port).await,
        None => tokio::net::lookup_host((host, port))
            .await
            .map(Iterator::collect),
    };
    found.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            LookupError {
                name: host.to_string(),
                source: e,
            },
        )
    })
}

/// The resolver of a client that has no policy to apply to the names it
/// connects to (a download of a URL): [`lookup`], the process' own resolver.
pub struct Names;

impl reqwest::dns::Resolve for Names {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addrs = lookup(name.as_str(), 0).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The resolver could not give the addresses of `name`.  Typed, so
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

/// The registry's own name was connected to, at a local address.
const REACHED_LOCAL: u8 = 1;
/// ... at a public address.
const REACHED_PUBLIC: u8 = 2;

/// The rule of one registry.
pub struct Policy {
    /// The registry's host, without the port.
    registry: String,
    allow: bool,
    /// What the connections made to the registry's own name went to
    /// (`REACHED_*`).  Taken from the addresses that were used, not asked
    /// again, so that a name that changes its answer cannot make a public
    /// registry private.
    reached: std::sync::atomic::AtomicU8,
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
            reached: Default::default(),
        }
    }

    /// Whether private addresses are allowed: the user said so, the
    /// registry is on one by its address, or every address it was reached
    /// at is one (a registry that was reached at a public address, once,
    /// is public).
    pub fn private_allowed(&self) -> bool {
        self.allow || local_host(&self.registry) || self.reached.load(Relaxed) == REACHED_LOCAL
    }

    /// Refuse a URL whose host is a private address written out (a name is
    /// checked when it is resolved).
    pub fn check_url(&self, url: &reqwest::Url) -> Result<(), String> {
        let Some(host) = url.host_str() else {
            return Err(format!("`{url}` has no host"));
        };
        let local = local_host(host);
        if local && !self.private_allowed() {
            return Err(format!(
                "refusing {}: a private address, and the registry {} is not on one \
                 (`allow-private-addresses = true` in the block of registries.conf of \
                 the registry, or of the registry it is a mirror of, allows it)",
                host, self.registry
            ));
        }
        Ok(())
    }

    /// The addresses of `name` that may be connected to.  The registry's
    /// own name is the first to say what the registry is: one that has a
    /// public address is public, and then it too is held to its public
    /// addresses.
    pub fn filter(&self, name: &str, addrs: Vec<SocketAddr>) -> std::io::Result<Vec<SocketAddr>> {
        let local = |a: &SocketAddr| {
            let local = local_ip(a.ip());
            // (a test names the loopback address it can reach public)
            #[cfg(test)]
            let local = local && !crate::client::hint_tests::pretend_public(name);
            local
        };
        if name == self.registry && !addrs.is_empty() {
            let reached = if addrs.iter().all(local) {
                REACHED_LOCAL
            } else {
                REACHED_PUBLIC
            };
            self.reached.fetch_or(reached, Relaxed);
        }
        if self.private_allowed() {
            return Ok(addrs);
        }
        let public: Vec<SocketAddr> = addrs.iter().filter(|a| !local(a)).copied().collect();
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

    #[test]
    fn a_registry_is_private_when_every_address_it_was_reached_at_is() {
        let at = |a: &str| vec![a.parse::<SocketAddr>().unwrap()];
        let policy = Policy::new("reg.example", false);
        assert!(!policy.private_allowed(), "not reached yet");
        policy.filter("reg.example", at("10.0.0.1:443")).unwrap();
        assert!(policy.private_allowed());
        // one public address makes it public, for good, and then its own
        // name is held to its public addresses too
        policy.filter("reg.example", at("8.8.8.8:443")).unwrap();
        assert!(!policy.private_allowed());
        assert!(policy.filter("reg.example", at("10.0.0.1:443")).is_err());
        assert!(!policy.private_allowed());
        assert!(policy
            .filter("reg.example", at("169.254.169.254:80"))
            .is_err());
        let mixed = vec![
            "10.0.0.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];
        assert_eq!(
            policy.filter("reg.example", mixed).unwrap(),
            at("8.8.8.8:443")
        );
        let url = reqwest::Url::parse("http://169.254.169.254/").unwrap();
        assert!(policy.check_url(&url).is_err());
        // an address written out, and the setting, decide without a connection
        assert!(Policy::new("10.0.0.1", false).private_allowed());
        assert!(!Policy::new("8.8.8.8", false).private_allowed());
        assert!(Policy::new("reg.example", true).private_allowed());
    }
}
