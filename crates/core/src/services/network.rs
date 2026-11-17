// SPDX-License-Identifier: Apache-2.0
//! Container Networking Service
//!
//! This module implements container networking:
//! - Container-to-container networking (--network=container:id)
//! - Network namespace management
//! - Network lifecycle handling

use crate::network::engine::ContainerNetworks;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::info;
use velarx_wire::request::NetworkMode;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid network mode: {0}")]
    InvalidMode(String),
    #[error("{0}")]
    Setup(#[from] velarx_netkernel::error::NetworkError),
}

pub type NetworkResult<T> = Result<T, NetworkError>;

/// Network manager for container networking
pub struct NetworkManager {
    /// The containers whose bridge or pasta networks the engine set up
    configured: RwLock<HashSet<String>>,
    /// Bridge networks and pasta, set by the daemon.
    engine: std::sync::OnceLock<Arc<ContainerNetworks>>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            configured: RwLock::new(HashSet::new()),
            engine: std::sync::OnceLock::new(),
        }
    }

    /// Set up bridge networks and pasta with ENGINE (once).
    pub fn set_engine(&self, engine: Arc<ContainerNetworks>) {
        let _ = self.engine.set(engine);
    }

    pub fn engine(&self) -> Option<&Arc<ContainerNetworks>> {
        self.engine.get()
    }

    /// Set up the network of MODE for the container whose process is PID.
    /// Bridge networks and pasta: the engine sets up every network of the
    /// container at once, the first time it is called for the container.
    pub async fn setup(
        &self,
        container_id: &str,
        mode: &NetworkMode,
        pid: i32,
    ) -> NetworkResult<()> {
        match (mode, self.engine.get()) {
            // The spec joined the namespace (resolved from the database when
            // the container starts), or the network provider makes it.
            (
                NetworkMode::Host
                | NetworkMode::Container(_)
                | NetworkMode::Ns(_)
                | NetworkMode::Provider(_),
                _,
            ) => {}
            // (a `none` container given a network by `network connect`: the
            // engine set it up before the creation, from its own record)
            (NetworkMode::Off, engine) if !engine.is_some_and(|e| e.is_prepared(container_id)) => {}
            (_, Some(engine)) => {
                if self.is_configured(container_id) {
                    return Ok(());
                }
                engine.setup(container_id, Some(pid)).await?;
                // (the monitor of the container holds the namespace now)
                engine.release_held(container_id);
                self.configured
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(container_id.to_string());
            }
            (
                NetworkMode::Unset
                | NetworkMode::Default
                | NetworkMode::Bridge(_)
                | NetworkMode::Pasta(_),
                None,
            ) => {
                return Err(NetworkError::InvalidMode(
                    "bridge networks and pasta are not available".to_string(),
                ));
            }
            (name, None) => {
                return Err(NetworkError::InvalidMode(format!(
                    "CNI network {name} not implemented"
                )));
            }
        }
        info!("Setup network for container {}: {:?}", container_id, mode);
        Ok(())
    }

    /// A new run of the container begins: what the last one set up is gone
    /// (its exit was recorded, and its network released, by the command the
    /// monitor ran, not by this process).
    pub fn begin(&self, container_id: &str) {
        self.configured
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(container_id);
    }

    fn is_configured(&self, container_id: &str) -> bool {
        self.configured
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(container_id)
    }

    /// Cleanup networking for a container
    pub async fn cleanup(&self, container_id: &str) -> NetworkResult<()> {
        let result = match self.engine.get() {
            Some(engine) => engine
                .teardown(container_id)
                .await
                .map_err(NetworkError::from),
            None => Ok(()),
        };
        self.configured
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(container_id);
        info!("Cleaned up network for container {}", container_id);
        result
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

/// The servers a container gets when the host has no usable nameserver
/// (the pair podman and Docker fall back to).
pub const DEFAULT_DNS: [&str; 2] = ["8.8.8.8", "8.8.4.4"];

/// What the /etc/resolv.conf of a container is made of, as podman's
/// `resolvconf.New`.
#[derive(Debug, Default)]
pub struct ResolvParams<'a> {
    /// The host's /etc/resolv.conf (what a local resolver stands for
    /// already looked up: `host_resolv_conf`).
    pub host: &'a str,
    /// The servers the container is given (`--dns`, a network's name
    /// server, the forwarder of pasta); with none, or with
    /// `keep_host_servers`, those of the host follow.
    pub nameservers: Vec<String>,
    pub keep_host_servers: bool,
    /// `--dns-search` (a lone `.` is none) or the search domains of the
    /// network.
    pub search: Vec<String>,
    /// The host's search domains follow the ones given.
    pub keep_host_search: bool,
    pub options: Vec<String>,
    /// The container has an IPv6 address: IPv6 servers of the host stay.
    pub ipv6: bool,
    /// The container is in the network namespace of the host: nothing of
    /// its resolv.conf is filtered.
    pub host_netns: bool,
}

fn resolv_lines(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .map(|l| l.split_whitespace().collect())
}

/// The addresses of the `nameserver` lines of a resolv.conf.
fn resolv_servers(text: &str) -> Vec<String> {
    resolv_lines(text)
        .filter_map(|w| match w.as_slice() {
            ["nameserver", ip] => Some(ip.to_string()),
            _ => None,
        })
        .filter(|ip| {
            ip.split('%')
                .next()
                .is_some_and(|a| a.parse::<std::net::IpAddr>().is_ok())
        })
        .collect()
}

/// The words of the last line that starts with KEY.
fn resolv_words(text: &str, key: &str) -> Vec<String> {
    resolv_lines(text)
        .filter(|w| w.first() == Some(&key))
        .last()
        .map(|w| w[1..].iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// The servers of the host's resolv.conf a container in another network
/// namespace can use: no loopback server (the loopback is not the host's),
/// no IPv6 one when the container has no IPv6, no link-local one (its zone
/// is the host's interface); the default servers when none is left.
fn usable_servers(text: &str, ipv6: bool, host_netns: bool) -> Vec<String> {
    let all = resolv_servers(text);
    if host_netns {
        return all;
    }
    let mut v: Vec<String> = all
        .into_iter()
        .filter(|s| {
            s.split('%')
                .next()
                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| !ip.is_loopback() && (ip.is_ipv4() || (ipv6 && !s.contains('%'))))
        })
        .collect();
    if v.is_empty() {
        v.extend(DEFAULT_DNS.map(String::from));
        if ipv6 {
            v.extend(["2001:4860:4860::8888".into(), "2001:4860:4860::8844".into()]);
        }
    }
    v
}

/// The /etc/resolv.conf of a container.
pub fn build_resolv_conf(p: &ResolvParams) -> String {
    let unset = |v: &[String]| -> Vec<String> {
        if v.iter().any(|s| s == ".") {
            Vec::new()
        } else {
            v.to_vec()
        }
    };
    let all_given = !p.nameservers.is_empty()
        && !p.options.is_empty()
        && !p.search.is_empty()
        && !p.keep_host_servers
        && !p.keep_host_search;
    let (mut servers, mut search, mut options) =
        (p.nameservers.clone(), unset(&p.search), p.options.clone());
    if !all_given {
        if servers.is_empty() || p.keep_host_servers {
            servers.extend(usable_servers(p.host, p.ipv6, p.host_netns));
        }
        if p.search.is_empty() || (p.keep_host_search && !search.is_empty()) {
            // (not the root, `.`, which systemd-resolved writes when it has
            // no domain: after a network's domain busybox's nslookup fails
            // on it, "Message too large"; podman copies it)
            search.extend(
                resolv_words(p.host, "search")
                    .into_iter()
                    .filter(|d| d != "."),
            );
        }
        if options.is_empty() {
            options = resolv_words(p.host, "options");
        }
    }
    // podman's order; a search line that is only the root (`.`, which
    // systemd-resolved writes) is none
    let mut out = String::new();
    if !search.is_empty() && search.join(" ").trim() != "." {
        out.push_str(&format!("search {}\n", search.join(" ")));
    }
    for s in &servers {
        out.push_str(&format!("nameserver {s}\n"));
    }
    if !options.is_empty() {
        out.push_str(&format!("options {}\n", options.join(" ")));
    }
    out
}

/// The resolv.conf of the host as a container in another network namespace
/// is to read it: a lone local resolver (systemd-resolved's stub, a
/// NetworkManager dnsmasq) stands for the file that lists its upstream
/// servers, which is read instead when there is one.
pub fn host_resolv_conf(host_netns: bool, read: impl Fn(&str) -> Option<String>) -> String {
    let text = read("/etc/resolv.conf").unwrap_or_default();
    if host_netns {
        return text;
    }
    let real = match resolv_servers(&text).as_slice() {
        [one] if one == "127.0.0.53" => "/run/systemd/resolve/resolv.conf",
        [one] if one == "127.0.0.1" => "/run/NetworkManager/no-stub-resolv.conf",
        _ => return text,
    };
    read(real).unwrap_or(text)
}

/// One `--add-host` value: `NAME[;NAME...]:IP`, IP an address or
/// `host-gateway`.  The names and the address, unresolved.
pub fn parse_extra_host(entry: &str) -> Result<(Vec<String>, String), String> {
    // (podman's words, cmd/podman/parse/net.go ValidateExtraHost)
    let (names, ip) = match entry.split_once(':') {
        Some((names, ip)) if !names.is_empty() => (names, ip),
        _ => return Err(format!("bad format for add-host: {entry:?}")),
    };
    if names.split(';').any(str::is_empty) {
        return Err(format!("hostname in add-host {entry:?} is empty"));
    }
    if ip != HOST_GATEWAY && ip.trim().parse::<std::net::IpAddr>().is_err() {
        return Err(format!("invalid IP address in add-host: {ip:?}"));
    }
    Ok((
        names.split(';').map(String::from).collect(),
        ip.trim().to_string(),
    ))
}

/// The value of `--add-host NAME:host-gateway`: the address of
/// host.containers.internal.
pub const HOST_GATEWAY: &str = "host-gateway";

/// Hosts file generator, in podman's order: the entries the user gives
/// (`--add-host`, then the base file), then the generated ones for the
/// names that are not there yet.
#[derive(Default)]
pub struct HostsConfig {
    user: Vec<(String, String)>,
    generated: Vec<(String, String)>,
}

impl HostsConfig {
    /// A hosts file with localhost.
    pub fn new() -> Self {
        Self {
            user: Vec::new(),
            generated: vec![
                ("127.0.0.1".to_string(), "localhost".to_string()),
                ("::1".to_string(), "localhost".to_string()),
            ],
        }
    }

    /// The host name and the container name on ADDRESS (the container's
    /// address on its first network, else the loopback).
    pub fn add_container(&mut self, ip: &str, hostname: &str, name: Option<&str>) {
        let mut names = hostname.to_string();
        if let Some(n) = name.filter(|n| !n.is_empty() && *n != hostname) {
            names.push(' ');
            names.push_str(n);
        }
        self.generated.push((ip.to_string(), names));
    }

    /// host.containers.internal.
    pub fn add_host(&mut self, ip: &str, names: &str) {
        self.generated.push((ip.to_string(), names.to_string()));
    }

    /// The entries of a hosts file (comments and blank lines left out).
    pub fn add_base(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut fields = line.split_whitespace();
            if let Some(ip) = fields.next() {
                let names: Vec<&str> = fields.collect();
                if !names.is_empty() {
                    self.user.push((ip.to_string(), names.join(" ")));
                }
            }
        }
    }

    /// `--add-host` entries; `host-gateway` is HOST_ADDRESS.  They come
    /// before the base file, so that they can override it.
    pub fn add_extra_hosts(
        &mut self,
        extra_hosts: &[String],
        host_address: Option<&str>,
    ) -> Result<(), String> {
        let mut extra = Vec::new();
        for entry in extra_hosts {
            let (names, ip) = parse_extra_host(entry)?;
            let ip = if ip == HOST_GATEWAY {
                host_address
                    .ok_or_else(|| {
                        format!(
                            "unable to replace {HOST_GATEWAY:?} of host entry {entry:?}: host containers internal IP address is empty"
                        )
                    })?
                    .to_string()
            } else {
                ip
            };
            extra.push((ip, names.join(" ")));
        }
        self.user.splice(0..0, extra);
        Ok(())
    }

    /// CONTENT (an /etc/hosts) with the address of the first entry of
    /// HOSTNAME that is not on the loopback replaced by IP; None when there
    /// is no such entry or it has IP already.
    pub fn with_new_address(content: &str, hostname: &str, ip: &str) -> Option<String> {
        let mut out = String::with_capacity(content.len() + ip.len());
        let mut done = false;
        for line in content.split_inclusive('\n') {
            let mut words = line.split_whitespace();
            let addr = words.next().unwrap_or_default();
            let own = !done
                && !line.trim_start().starts_with('#')
                && addr
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|a| !a.is_loopback())
                && words.any(|w| w == hostname);
            if !own {
                out.push_str(line);
                continue;
            }
            done = true;
            if addr == ip {
                return None;
            }
            let at = line.find(addr).unwrap_or(0);
            out.push_str(&line[..at]);
            out.push_str(ip);
            out.push_str(&line[at + addr.len()..]);
        }
        done.then_some(out)
    }

    /// Generate /etc/hosts content
    pub fn generate_hosts(&self) -> String {
        let mut taken: HashSet<&str> = HashSet::new();
        let mut out = String::new();
        for (ip, names) in &self.user {
            taken.extend(names.split(' '));
            out.push_str(&format!("{ip}\t{names}\n"));
        }
        for (ip, names) in &self.generated {
            let free: Vec<&str> = names.split(' ').filter(|n| !taken.contains(n)).collect();
            if !free.is_empty() {
                out.push_str(&format!("{ip}\t{}\n", free.join(" ")));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(ip: &str) -> HostsConfig {
        let mut h = HostsConfig::new();
        h.add_container(ip, "web", Some("w1"));
        h
    }

    #[test]
    fn the_address_of_the_container_changes() {
        let mut h = own("10.0.0.5");
        h.add_extra_hosts(&["other:10.9.9.9".to_string()], None)
            .unwrap();
        let content = h.generate_hosts();
        assert_eq!(
            content,
            "10.9.9.9\tother\n127.0.0.1\tlocalhost\n::1\tlocalhost\n10.0.0.5\tweb w1\n"
        );
        let new = HostsConfig::with_new_address(&content, "web", "10.0.0.7").unwrap();
        assert!(new.ends_with("10.0.0.7\tweb w1\n"));
        assert_eq!(HostsConfig::with_new_address(&new, "web", "10.0.0.7"), None);
        // On the loopback only: nothing to change.
        let mut lo = HostsConfig::new();
        lo.add_container("127.0.0.1", "web", None);
        let lo = lo.generate_hosts();
        assert_eq!(HostsConfig::with_new_address(&lo, "web", "10.0.0.7"), None);
        assert_eq!(HostsConfig::with_new_address("", "web", "10.0.0.7"), None);
    }

    #[test]
    fn add_host_comes_first_and_overrides() {
        let mut h = HostsConfig::new();
        h.add_host(
            "169.254.1.2",
            "host.containers.internal host.docker.internal",
        );
        h.add_container("127.0.0.1", "web", Some("w1"));
        h.add_base("10.0.0.1 base-only web\n127.0.0.1 localhost\n");
        h.add_extra_hosts(
            &[
                "host.containers.internal:10.1.1.1".to_string(),
                "a;b:10.2.2.2".to_string(),
                "gw:host-gateway".to_string(),
            ],
            Some("169.254.1.2"),
        )
        .unwrap();
        assert_eq!(
            h.generate_hosts(),
            "10.1.1.1\thost.containers.internal\n10.2.2.2\ta b\n169.254.1.2\tgw\n\
             10.0.0.1\tbase-only web\n127.0.0.1\tlocalhost\n\
             169.254.1.2\thost.docker.internal\n127.0.0.1\tw1\n"
        );
    }

    #[test]
    fn add_host_is_checked() {
        for bad in [
            "bad:notanip",
            "baz=10.0.0.2",
            ":1.1.1.1",
            "x:",
            "a;:1.1.1.1",
        ] {
            assert!(parse_extra_host(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_extra_host("a;b:fd00::1").unwrap(),
            (
                vec!["a".to_string(), "b".to_string()],
                "fd00::1".to_string()
            )
        );
        assert!(parse_extra_host("x:host-gateway").is_ok());
        let mut h = HostsConfig::new();
        assert!(h
            .add_extra_hosts(&["x:host-gateway".to_string()], None)
            .is_err());
    }

    #[test]
    fn base_hosts_entries_are_added() {
        let mut h = HostsConfig::new();
        h.add_base("# comment\n10.0.0.2 testname\n\n192.168.1.1\tabc  def # x\nlonely\n");
        let out = h.generate_hosts();
        assert!(out.contains("10.0.0.2\ttestname\n"));
        assert!(out.contains("192.168.1.1\tabc def\n"));
        assert!(!out.contains("lonely") && !out.contains('#'));
    }

    fn params<'a>(host: &'a str) -> ResolvParams<'a> {
        ResolvParams {
            host,
            ..ResolvParams::default()
        }
    }

    #[test]
    fn resolv_conf_of_the_host_is_the_base() {
        let host = "search corp.example.\nnameserver 192.168.1.1\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\nnameserver 2001:db8::1\noptions edns0 trust-ad\n";
        // pasta: the forwarder, then the host's, with its search and options;
        // no loopback, no IPv6 without IPv6
        let mut p = params(host);
        p.nameservers = vec!["169.254.1.1".into()];
        p.keep_host_servers = true;
        assert_eq!(
            build_resolv_conf(&p),
            "search corp.example.\nnameserver 169.254.1.1\nnameserver 192.168.1.1\noptions edns0 trust-ad\n"
        );
        p.ipv6 = true;
        assert!(build_resolv_conf(&p).contains("nameserver 2001:db8::1\n"));
        assert!(!build_resolv_conf(&p).contains("fe80"));
        // the host's network namespace: all of it
        let mut p = params(host);
        p.host_netns = true;
        assert!(build_resolv_conf(&p).contains("nameserver 127.0.0.1\n"));
    }

    #[test]
    fn resolv_conf_without_a_usable_server_gets_the_default_pair() {
        // podman's fallback too (resolvconf.go defaultIPv4Dns)
        let p = params("nameserver 127.0.0.53\n");
        assert_eq!(
            build_resolv_conf(&p),
            "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
        );
        let mut p = params("");
        p.ipv6 = true;
        assert!(build_resolv_conf(&p).contains("2001:4860:4860::8888"));
    }

    #[test]
    fn dns_options_replace_the_host_ones() {
        let host = "search corp.example.\nnameserver 192.168.1.1\noptions edns0\n";
        let mut p = params(host);
        p.nameservers = vec!["1.1.1.1".into()];
        p.search = vec![".".into()];
        p.options = vec!["ndots:2".into()];
        assert_eq!(
            build_resolv_conf(&p),
            "nameserver 1.1.1.1\noptions ndots:2\n"
        );
        // `.` alone: no search line
        p.options.clear();
        p.keep_host_search = true;
        assert_eq!(build_resolv_conf(&p), "nameserver 1.1.1.1\noptions edns0\n");
        // a network's search domain, then the host's
        p.search = vec!["dns.podman".into()];
        assert!(build_resolv_conf(&p).contains("search dns.podman corp.example.\n"));
    }

    #[test]
    fn the_root_domain_of_the_host_is_no_search() {
        let mut p = params("nameserver 192.168.1.1\nsearch .\n");
        assert_eq!(build_resolv_conf(&p), "nameserver 192.168.1.1\n");
        // the root among other domains is not copied either (podman's is)
        p.host = "nameserver 192.168.1.1\nsearch . lab.test\n";
        assert_eq!(
            build_resolv_conf(&p),
            "search lab.test\nnameserver 192.168.1.1\n"
        );
        // after a network's domain
        p.search = vec!["dns.podman".into()];
        p.keep_host_search = true;
        p.host = "nameserver 192.168.1.1\nsearch .\n";
        assert!(build_resolv_conf(&p).starts_with("search dns.podman\n"));
        p.search.clear();
        p.keep_host_search = false;
        // CRLF, comments, leading blanks, an `options` line before the last
        p.host = "options ndots:1\r\n  nameserver 10.0.0.1 # lan\r\n#nameserver 10.0.0.2\r\nsearch a.test\r\noptions rotate\r\n";
        assert_eq!(
            build_resolv_conf(&p),
            "search a.test\nnameserver 10.0.0.1\noptions rotate\n"
        );
    }

    #[test]
    fn a_local_resolver_stands_for_its_upstream_file() {
        let read = |p: &str| match p {
            "/etc/resolv.conf" => Some("nameserver 127.0.0.53\nsearch .\n".to_string()),
            "/run/systemd/resolve/resolv.conf" => Some("nameserver 10.0.0.1\n".to_string()),
            _ => None,
        };
        assert_eq!(host_resolv_conf(false, read), "nameserver 10.0.0.1\n");
        assert!(host_resolv_conf(true, read).contains("127.0.0.53"));
        let none =
            |p: &str| (p == "/etc/resolv.conf").then(|| "nameserver 127.0.0.53\n".to_string());
        assert!(host_resolv_conf(false, none).contains("127.0.0.53"));
    }
}
