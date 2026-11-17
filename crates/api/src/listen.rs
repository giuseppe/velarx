// SPDX-License-Identifier: Apache-2.0
//! Where the API listens: the unix socket (the default and, unless TCP is
//! asked for, the only listener), and TCP.
//!
//! TCP with no address binds the loopback addresses only (127.0.0.1 and
//! ::1).  Another address is explicit (`tcp://HOST:PORT`) and is bound.  A
//! TCP listener that is named is warned about unless TLS is on (`tls_cert`).
//! Whoever reaches the API controls the engine with this process's user, so
//! every TCP listener asks for a bearer token (`[api] token_file`), unless
//! `allow_unauthenticated` says that whoever can connect may control the
//! engine.

use crate::config::DEFAULT_TCP_PORT;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

/// A place to listen, as `--listen` or `[api] listen` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    Unix(PathBuf),
    /// The addresses of a `tcp://` place: more than one for the loopback
    /// of both families, or a name that resolves to several
    Tcp(Vec<SocketAddr>),
}

/// The loopback addresses of a port.
pub fn loopback(port: u16) -> Vec<SocketAddr> {
    vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
    ]
}

/// `unix:///PATH`, `tcp://HOST:PORT`, `tcp://:PORT` or `tcp://` (the
/// loopback addresses, on `PORT` or [`DEFAULT_TCP_PORT`]).  A name is
/// resolved here, before the process confines itself.
pub fn parse(uri: &str) -> Result<Place, String> {
    if let Some(path) = uri.strip_prefix("unix://") {
        if !path.starts_with('/') {
            return Err(format!(
                "{uri}: the path of a unix socket must be absolute (unix:///PATH)"
            ));
        }
        return Ok(Place::Unix(PathBuf::from(path)));
    }
    let Some(addr) = uri.strip_prefix("tcp://") else {
        return Err(format!("{uri}: unix:///PATH or tcp://HOST:PORT"));
    };
    let addr = addr.trim_end_matches('/');
    let (host, port) = match addr.rsplit_once(':') {
        // (an IPv6 address has colons of its own: it is in brackets
        // when it has a port)
        Some((host, port)) if !host.contains(':') || host.ends_with(']') => {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("{uri}: {port:?} is not a port"))?;
            (host, port)
        }
        _ => (addr, DEFAULT_TCP_PORT),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Ok(Place::Tcp(loopback(port)));
    }
    let resolved: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{uri}: {e}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!("{uri}: no address"));
    }
    Ok(Place::Tcp(resolved))
}

/// The warning for a TCP listener that is named, in podman's words for
/// `system service tcp://...` (loopback or not).
pub const TCP_WARNING: &str = "Using the velarx API service with TCP sockets without TLS is not \
     recommended, please see the velarx-api(8) manpage for details";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tcp_place_with_no_host_is_the_loopback() {
        for uri in ["tcp://:9000", "tcp://:9000/"] {
            assert_eq!(parse(uri).unwrap(), Place::Tcp(loopback(9000)), "{uri}");
        }
        assert_eq!(
            parse("tcp://").unwrap(),
            Place::Tcp(loopback(DEFAULT_TCP_PORT))
        );
        assert_eq!(
            parse("tcp://127.0.0.1:1").unwrap(),
            Place::Tcp(vec!["127.0.0.1:1".parse().unwrap()])
        );
        assert_eq!(
            parse("tcp://[::1]:2").unwrap(),
            Place::Tcp(vec!["[::1]:2".parse().unwrap()])
        );
        assert_eq!(
            parse("unix:///run/x.sock").unwrap(),
            Place::Unix("/run/x.sock".into())
        );
        for bad in ["unix://x", "http://x", "tcp://127.0.0.1:x", "x", ""] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_warning_is_podmans() {
        assert!(TCP_WARNING.starts_with("Using the velarx API service with TCP sockets without TLS is not recommended, please see"));
    }
}
