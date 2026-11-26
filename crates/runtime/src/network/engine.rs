// SPDX-License-Identifier: Apache-2.0
//! The networks of containers: what a container asks for when it is
//! created (checked, addresses allocated in the database), and the setup
//! and teardown of its network namespace (bridge networks or pasta).
//!
//! This is the narrow interface of the container lifecycle:
//!
//! * `plan` and `commit` at create time (`plan` before the root file system
//!   is written: it gives the nameservers and host address of
//!   `/etc/resolv.conf` and `/etc/hosts`; `commit` once the container
//!   record exists);
//! * `prepare_netns(id)` makes the namespace of a container before the
//!   runtime creates it, `setup(id, pid)` sets its network up once it
//!   exists (from the daemon or the daemonless engine), `teardown(id)` once
//!   the container stopped;
//! * `connect`, `disconnect` for `network connect/disconnect`, and
//!   `network_removed` for `network rm/prune`.
//!
//! The namespace is held by descriptors (see `netns`): this engine's while it
//! sets the network up, the monitor's for the life of the container.  A
//! container with the annotation `io.velarx.shareableNetworkNamespace=true`
//! takes a namespace from the pool instead (see `pool`), the only
//! namespaces that are pinned.

use super::pasta;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use velarx_config::BridgeConfig;
use velarx_db::sync::BlockingDb;
use velarx_db::{Database, Ip6Choice, IpChoice};
use velarx_netdetach::def::NetworkDef;
use velarx_netdetach::spec::{parse_spec, Mode, NetSpec};
use velarx_netdetach::teardown::{check_id, cni_attachment, Detach, CNI_IFNAME};
use velarx_netkernel::bridge::{self, BridgeContainer, BridgeOptions, NetnsFate};
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_netkernel::firewall::Firewall;
use velarx_netkernel::netns::{Netns, Records};
use velarx_wire::addr::{self, PortSpec, Subnet, Subnet6};
use velarx_wire::request::NetworkMode;

/// The annotation that lets a container share a pooled network namespace.
pub const SHAREABLE_ANNOTATION: &str = "io.velarx.shareableNetworkNamespace";
/// The search domain of the containers on DNS networks.
pub const DNS_SEARCH: &str = velarx_netkernel::dns::DOMAIN;

/// An overlap of a subnet is a refusal of it; any other error is the
/// failure of the check.
fn overlap_error(e: std::io::Error) -> NetworkError {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        NetworkError::InvalidConfig(e.to_string())
    } else {
        NetworkError::Netlink(e.to_string())
    }
}

/// A static IPv4 address asked for on N: podman's words for one outside
/// its subnet.
fn check_static_ip(n: &NetworkDef, ip: Ipv4Addr) -> NetworkResult<()> {
    if !n.subnet.contains(ip) {
        return Err(NetworkError::InvalidConfig(format!(
            "requested static ip {ip} not in any subnet on network {}",
            n.name
        )));
    }
    if !n.subnet.is_host(ip) || ip == n.gateway {
        return Err(NetworkError::InvalidConfig(format!(
            "the address `{ip}` is not usable in the network `{}`",
            n.name
        )));
    }
    Ok(())
}

/// A static IPv6 address asked for on N, as `check_static_ip`.
fn check_static_ip6(n: &NetworkDef, ip: Ipv6Addr) -> NetworkResult<()> {
    let Some(s) = n.subnet6.filter(|s| s.contains(ip)) else {
        return Err(NetworkError::InvalidConfig(format!(
            "requested static ip {ip} not in any subnet on network {}",
            n.name
        )));
    };
    if !s.is_host(ip) || Some(ip) == n.gateway6 {
        return Err(NetworkError::InvalidConfig(format!(
            "the address `{ip}` is not usable in the network `{}`",
            n.name
        )));
    }
    Ok(())
}

/// The setup of a container as [`Engine::specs`] reads it: the
/// message of the error when the database has one that cannot be read.
pub type SpecRead = Result<NetSpec, String>;

/// What a create asks for.
#[derive(Debug, Clone, Default)]
pub struct NetRequest {
    pub name: String,
    pub network_mode: NetworkMode,
    pub networks: Vec<String>,
    pub ports: Vec<PortSpec>,
    pub ip: Option<String>,
    /// `--ip6`.
    pub ip6: Option<String>,
    pub mac: Option<String>,
    /// `--network-alias`: only a bridge network has names.
    pub aliases: Vec<String>,
    /// The other names a container has on a DNS network: its short ID (as
    /// Docker's) and its `--hostname`.
    pub implicit_aliases: Vec<String>,
    pub annotations: HashMap<String, String>,
    /// The annotations of the pod the container is the infra container of,
    /// and the subnets the node gives its pods: for the CNI plugins only
    /// (not annotations of the container).
    pub cni_annotations: BTreeMap<String, String>,
    pub cni_ip_ranges: Vec<String>,
}

/// What `/etc/resolv.conf` and `/etc/hosts` of the container get.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EtcInfo {
    /// The name servers the container is given; those of the host follow
    /// when `keep_host_servers`, or when there is none.
    pub nameservers: Vec<String>,
    pub keep_host_servers: bool,
    pub search: Vec<String>,
    /// The container has an IPv6 address.
    pub ipv6: bool,
    /// host.containers.internal.
    pub host_address: Option<String>,
    /// The address of the container when its network namespace gets it
    /// from the host (pasta).
    pub address: Option<String>,
}

/// The result of `plan`, for `commit`.
#[derive(Debug, Clone)]
pub struct Planned {
    pub spec: NetSpec,
    nets: Vec<NetworkDef>,
    /// What each of `nets` was asked for.
    options: Vec<NetOptions>,
    aliases: Vec<String>,
    pub etc: EtcInfo,
    /// The published ports (indexes of `spec.ports`) whose host port was
    /// picked here, not given: `commit` records them for the container.
    auto_ports: Vec<usize>,
}

/// An interface of a container, for inspect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub network: String,
    pub network_id: String,
    pub ifname: String,
    pub ip: Option<Ipv4Addr>,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub mac: String,
    pub aliases: Vec<String>,
    /// On a dual-stack network: the address, its prefix and the gateway.
    pub ip6: Option<Ipv6Addr>,
    pub prefix6: u8,
    pub gateway6: Option<Ipv6Addr>,
    /// The gateway is no route of the container: an internal network,
    /// and no DNS server on it either (inspect shows no gateway, as
    /// podman).
    pub no_gateway: bool,
}

/// What `setup` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkStatus {
    pub mode: Mode,
    pub interfaces: Vec<Interface>,
    /// `prepare` pinned and configured the namespace (a shareable one,
    /// maybe from the pool) before the runtime created the container.
    pub prepared: bool,
}

pub struct EngineOptions {
    /// The run root of the daemon: the network state goes below.
    pub state_dir: PathBuf,
    /// The store's database: its namespaces tables record the namespaces.
    pub db_path: PathBuf,
    pub bridge: BridgeConfig,
    /// The nftables table (`velarx`).
    pub table: String,
    /// `velarx`, for the DNS server.
    pub dns_exe: PathBuf,
    /// The CNI plugins and configurations.
    pub cni: velarx_config::CniConfig,
    /// The network providers of the configuration
    pub providers: Vec<velarx_netdetach::provider::ProviderRef>,
}

/// What `network connect` asks: the container, and the addresses it wants
/// on the network (parsed once, where the words are:
/// [`ConnectRequest::parse`]).
#[derive(Clone, Copy)]
pub struct ConnectRequest<'a> {
    pub container_id: &'a str,
    pub container_name: &'a str,
    pub ip: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    pub mac: Option<[u8; 6]>,
    /// Further names of the container on the network
    pub aliases: &'a [String],
}

impl<'a> ConnectRequest<'a> {
    /// The request of the words of the command (an empty word: none given).
    pub fn parse(
        container: (&'a str, &'a str),
        ip: Option<&str>,
        ip6: Option<&str>,
        mac: Option<&str>,
        aliases: &'a [String],
    ) -> NetworkResult<Self> {
        let invalid = |what: &str, w: &str| {
            NetworkError::InvalidConfig(format!("invalid {what} address `{w}`"))
        };
        Ok(Self {
            container_id: container.0,
            container_name: container.1,
            ip: ip
                .filter(|w| !w.is_empty())
                .map(|w| w.parse().map_err(|_| invalid("IPv4", w)))
                .transpose()?,
            ip6: ip6
                .filter(|w| !w.is_empty())
                .map(|w| w.parse().map_err(|_| invalid("IPv6", w)))
                .transpose()?,
            mac: mac
                .filter(|w| !w.is_empty())
                .map(|w| {
                    addr::parse_mac(w).ok_or_else(|| {
                        NetworkError::InvalidConfig(format!("address {w}: invalid MAC address"))
                    })
                })
                .transpose()?,
            aliases,
        })
    }
}

pub struct ContainerNetworks {
    pub(super) db: Database,
    pub(super) cfg: BridgeConfig,
    /// `<run>/networks`
    pub(super) run: PathBuf,
    /// The store's database
    pub(super) db_path: PathBuf,
    pub(super) bridge: BridgeOptions,
    cni: velarx_netkernel::cni::CniConfig,
    /// What releases a container's network: the engine and the monitors run it
    pub(super) detach: Detach,
    /// The links of the namespace of the engine are not its own (a rootless
    /// daemon): bridges live in the rootless network namespace.
    pub(super) rootless: bool,
    /// The rootless network namespace can be made: root in the user
    /// namespace of the rootless user (pasta, which connects it, is required
    /// where one is made: `bridge_opts`).
    rootless_netns: bool,
    pasta: std::sync::Arc<pasta::Supervisor>,
    /// The pasta started before the runtime created the container
    /// (`prepare_pasta`), by container.
    early_pasta: std::sync::Mutex<HashMap<String, EarlyPasta>>,
    /// The namespaces of the containers this process is setting up, held
    /// open from their creation (`prepare_netns`) until the setup is done
    /// (`release_held`): the monitor holds them after.
    held: std::sync::Mutex<HashMap<String, Netns>>,
    /// Containers whose network was set up before the runtime created them
    /// (`prepare`, `prepare_own`): `setup` has nothing left to do.
    prepared: std::sync::Mutex<std::collections::HashSet<String>>,
    /// The monitors of the containers this process is starting, by
    /// container (`monitor_started`): each holds the namespace of its
    /// container, and is recorded as its holder once it is recorded.
    monitors: std::sync::Mutex<HashMap<String, i32>>,
    /// The namespaces of the containers, who they are and who holds them.
    pub(super) records: Records,
}

/// A pasta that starts while the container is being created.
struct EarlyPasta {
    started: tokio::task::JoinHandle<std::io::Result<()>>,
    argv: Vec<String>,
    /// The namespace pasta was started on: `/proc/PID/fd/N` of the monitor,
    /// which holds it for as long as it is the container's.
    netns: PathBuf,
    pid_file: PathBuf,
    log_file: PathBuf,
}

/// What a container joins, from the database: its own file, or the namespace
/// of another container (a descriptor).
pub enum Shared {
    /// `ns:PATH`: the namespace of that file, joined by its path.
    Path(PathBuf),
    /// `container:ID`: the namespace of that container, opened.
    Held(Netns),
}

impl Shared {
    /// The path the spec of the container created now names (the monitor
    /// writes the one that is valid when the container starts).
    pub fn spec_path(&self) -> String {
        match self {
            Shared::Path(p) => p.to_string_lossy().into_owned(),
            Shared::Held(_) => velarx_nsid::HELD.to_string(),
        }
    }
}

/// Whether the process may manage the links of its network namespace: root
/// in the user namespace that owns it.
fn owns_network_namespace() -> Result<bool, velarx_base::ids::IdsError> {
    if !rustix::process::geteuid().is_root() {
        return Ok(false);
    }
    if !crate::userns::rootless::in_user_namespace()? {
        return Ok(true);
    }
    use std::os::unix::fs::MetadataExt;
    let (Ok(net), Ok(user)) = (
        std::fs::File::open("/proc/self/ns/net"),
        std::fs::metadata("/proc/self/ns/user"),
    ) else {
        return Ok(false);
    };
    let Ok(owner) = velarx_sys::ns::owner_user_namespace(std::os::fd::AsFd::as_fd(&net)) else {
        return Ok(false);
    };
    Ok(std::fs::File::from(owner)
        .metadata()
        .map(|m| m.ino() == user.ino())
        .unwrap_or(false))
}

/// The address a container with pasta has in its network namespace: the
/// one `-a` gives, else the address the host goes out with (which pasta
/// copies).
pub fn pasta_address(options: &[String]) -> Option<IpAddr> {
    let mut given = None;
    let mut it = options.iter();
    while let Some(o) = it.next() {
        if o == "-a" || o == "--address" {
            given = it.next().map(String::as_str);
        } else if let Some(v) = o.strip_prefix("--address=") {
            given = Some(v);
        }
    }
    match given {
        Some(a) => a.parse().ok(),
        None => outbound_address(),
    }
}

/// The address the host uses to reach the outside (the source address of
/// its default route); nothing is sent.
pub fn outbound_address() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:9").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

/// The interface a CNI result describes: its addresses (the IPv4 and the
/// IPv6 one), their gateways and the hardware address.
fn cni_interface(network: &str, result: &serde_json::Value) -> Option<Interface> {
    let ips = velarx_netkernel::cni::result_addresses(result, CNI_IFNAME);
    let v4 = ips.iter().find(|a| a.address.is_ipv4());
    let v6 = ips.iter().find(|a| a.address.is_ipv6());
    let first = v4.or(v6)?;
    Some(Interface {
        network: network.to_string(),
        network_id: network.to_string(),
        ifname: CNI_IFNAME.to_string(),
        ip: match v4.map(|a| a.address) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        },
        prefix: v4.map_or(0, |a| a.prefix),
        gateway: match v4.and_then(|a| a.gateway) {
            Some(IpAddr::V4(g)) => g,
            _ => Ipv4Addr::UNSPECIFIED,
        },
        mac: velarx_netkernel::cni::result_mac(result, CNI_IFNAME).unwrap_or_default(),
        aliases: Vec::new(),
        ip6: match v6.map(|a| a.address) {
            Some(IpAddr::V6(ip)) => Some(ip),
            _ => None,
        },
        prefix6: v6.map_or(0, |a| a.prefix),
        gateway6: match v6.and_then(|a| a.gateway) {
            Some(IpAddr::V6(g)) => Some(g),
            _ => None,
        },
        no_gateway: first.gateway.is_none(),
    })
}

/// The annotations that tell the CNI plugins which pod a container is the
/// infra container of (the labels of the pod of the kubelet).
pub const CNI_POD_KEYS: [&str; 3] = [
    "io.kubernetes.pod.name",
    "io.kubernetes.pod.namespace",
    "io.kubernetes.pod.uid",
];

/// `ADDRESS/PREFIX` of an IPv4 or IPv6 network.
fn is_cidr(s: &str) -> bool {
    s.split_once('/').is_some_and(
        |(addr, len)| match (addr.parse::<IpAddr>(), len.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(l)) => l <= 32,
            (Ok(IpAddr::V6(_)), Ok(l)) => l <= 128,
            _ => false,
        },
    )
}

fn is_default_name(n: &str) -> bool {
    matches!(n, "" | "default" | "bridge" | "private")
}

/// `--network` of the default network: nothing, `default`, `bridge` or
/// `private`.
fn is_default_mode(m: &NetworkMode) -> bool {
    matches!(
        m,
        NetworkMode::Unset
            | NetworkMode::Default
            | NetworkMode::Bridge(None)
            | NetworkMode::Private
    )
}

/// What `--network NAME:OPTIONS` asks of one network: `ip=`, `ip6=`, `mac=`,
/// `alias=` (any number of times) and `interface_name=`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NetOptions {
    ip: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
    mac: Option<[u8; 6]>,
    aliases: Vec<String>,
    ifname: Option<String>,
}

/// Give `slot` its VALUE: once.
fn set_once<T>(slot: &mut Option<T>, key: &str, value: T) -> NetworkResult<()> {
    match slot.replace(value) {
        None => Ok(()),
        Some(_) => Err(NetworkError::InvalidConfig(format!(
            "the network option `{key}` is given more than once"
        ))),
    }
}

impl NetOptions {
    /// The options of the list `a=b,c=d` of the network `network`.
    fn parse(network: &str, list: &str) -> NetworkResult<Self> {
        let bad = |what: &str, v: &str| {
            NetworkError::InvalidConfig(format!("invalid {what} `{v}` of the network `{network}`"))
        };
        let mut o = Self::default();
        for option in list.split(',').filter(|o| !o.is_empty()) {
            let (key, v) = option
                .split_once('=')
                .ok_or_else(|| bad("network option", option))?;
            match key {
                "ip" => set_once(
                    &mut o.ip,
                    key,
                    v.parse().map_err(|_| bad("IPv4 address", v))?,
                )?,
                "ip6" => set_once(
                    &mut o.ip6,
                    key,
                    v.parse().map_err(|_| bad("IPv6 address", v))?,
                )?,
                "mac" => set_once(
                    &mut o.mac,
                    key,
                    addr::parse_mac(v).ok_or_else(|| bad("MAC address", v))?,
                )?,
                "alias" if !v.is_empty() => o.aliases.push(v.to_string()),
                "interface_name" if addr::valid_ifname(v) => {
                    set_once(&mut o.ifname, key, v.to_string())?
                }
                "interface_name" => return Err(bad("interface name", v)),
                _ => return Err(bad("network option", option)),
            }
        }
        Ok(o)
    }
}

/// The first `ethN` that is none of `taken`.
fn free_ifname<'a>(taken: impl Iterator<Item = &'a str> + Clone) -> String {
    (0..)
        .map(|i| format!("eth{i}"))
        .find(|n| !taken.clone().any(|t| t == n))
        .expect("an endless list of names")
}

/// The interface names of the networks: the one each asked for, else the
/// first `ethN` that no other network has.  Two networks cannot ask for one
/// name.
fn ifnames(options: &[NetOptions]) -> NetworkResult<Vec<String>> {
    let asked: Vec<&str> = options.iter().filter_map(|o| o.ifname.as_deref()).collect();
    for (i, name) in asked.iter().enumerate() {
        if asked[..i].contains(name) {
            return Err(NetworkError::InvalidConfig(format!(
                "the interface name `{name}` is asked for by more than one network"
            )));
        }
    }
    let mut names: Vec<String> = Vec::new();
    for o in options {
        let name = match &o.ifname {
            Some(n) => n.clone(),
            None => free_ifname(
                asked
                    .iter()
                    .copied()
                    .chain(names.iter().map(String::as_str)),
            ),
        };
        names.push(name);
    }
    Ok(names)
}

/// A network by name (the CNI network of `cni:NAME` may be empty) and its
/// options.
type NamedNet = (String, NetOptions);

/// The networks of a request: the mode and the bridge networks.
fn parse_modes(req: &NetRequest) -> NetworkResult<(Mode, Vec<NamedNet>, Vec<String>, bool)> {
    // `a,b` is a list of networks
    let names: Vec<NetworkMode> = if !req.networks.is_empty() {
        req.networks
            .iter()
            .flat_map(|n| NetworkMode::parse(n).pieces())
            .collect()
    } else {
        req.network_mode.pieces()
    };
    let mut mode = None;
    let mut bridges = Vec::new();
    let mut pasta_options = Vec::new();
    let mut implicit = false;
    for n in &names {
        let m = match n {
            NetworkMode::Unset
            | NetworkMode::Default
            | NetworkMode::Private
            | NetworkMode::Bridge(None) => {
                // `bridge` is asked for (podman's rootless `--network
                // bridge` is the default network too); nothing or
                // `default` is the default mode.
                implicit = *n != NetworkMode::Bridge(None);
                bridges.push((String::new(), NetOptions::default()));
                Mode::Bridge
            }
            // the default network, with options
            NetworkMode::Bridge(Some(options)) => {
                bridges.push((String::new(), NetOptions::parse("bridge", options)?));
                Mode::Bridge
            }
            NetworkMode::Host => Mode::Host,
            NetworkMode::Off => Mode::None,
            NetworkMode::Pasta(options) => {
                pasta_options.extend(
                    options
                        .iter()
                        .flat_map(|o| o.split(','))
                        .filter(|o| !o.is_empty())
                        .map(String::from),
                );
                Mode::Pasta
            }
            NetworkMode::Provider(_) => continue,
            NetworkMode::Container(_) | NetworkMode::Ns(_) => Mode::Other,
            NetworkMode::Network(n) if n == "slirp4netns" || n.starts_with("slirp4netns:") => {
                return Err(NetworkError::InvalidConfig(
                    "the network mode slirp4netns is not supported: use pasta (`--network pasta`), \
                     which is what rootless containers get by default"
                        .into(),
                ))
            }
            NetworkMode::Network(n) if n.starts_with("cni:") => {
                let name = &n["cni:".len()..];
                if !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
                {
                    return Err(NetworkError::InvalidConfig(format!(
                        "invalid CNI network name `{name}`"
                    )));
                }
                bridges.push((name.to_string(), NetOptions::default()));
                Mode::Cni
            }
            // a network by name and its options (`pod` is no name of one:
            // found as a network)
            n @ (NetworkMode::Network(_) | NetworkMode::Pod) => {
                let text = n.to_string();
                let (name, options) = text.split_once(':').unwrap_or((&text, ""));
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
                {
                    return Err(NetworkError::InvalidConfig(format!(
                        "invalid network mode `{text}`"
                    )));
                }
                bridges.push((name.to_string(), NetOptions::parse(name, options)?));
                Mode::Bridge
            }
        };
        mode = Some(match (mode, m) {
            (None, m) => m,
            (Some(a), b) if a == b => a,
            // pasta or a bridge with an overlay: the overlay is set up apart.
            (Some(a), Mode::Other) | (Some(Mode::Other), a) => a,
            (Some(a), b) => {
                return Err(NetworkError::InvalidConfig(format!(
                    "the network modes {a:?} and {b:?} cannot be combined"
                )))
            }
        });
    }
    // Only an overlay: not ours.
    let mode = mode.unwrap_or(Mode::Other);
    Ok((
        mode,
        bridges,
        pasta_options,
        implicit && names.iter().all(is_default_mode),
    ))
}

impl ContainerNetworks {
    pub fn new(db: Database, opts: EngineOptions) -> Result<Self, velarx_base::ids::IdsError> {
        let run = opts.state_dir.join("networks");
        let rootless = !owns_network_namespace()?;
        let bridge = BridgeOptions {
            state_dir: run.clone(),
            firewall: Firewall {
                table: opts.table.clone(),
            },
            dns_exe: opts.dns_exe.clone(),
            netns: None,
        };
        let rootless_netns = rootless && rustix::process::geteuid().is_root();
        let cni = velarx_netkernel::cni::CniConfig {
            conf_dir: opts.cni.conf_dir,
            bin_dirs: opts.cni.bin_dirs,
            cache_dir: opts.cni.cache_dir,
            timeout: std::time::Duration::from_secs(opts.cni.timeout_secs),
        };
        let pool_dir = opts.state_dir.join("netns-pool");
        let detach = Detach {
            run: run.clone(),
            pool_dir: pool_dir.clone(),
            state_dir: opts.state_dir.clone(),
            db: opts.db_path.clone(),
            bridge: bridge.clone(),
            cfg: opts.bridge.clone(),
            cni: cni.clone(),
            rootless,
            rootless_netns,
            providers: opts.providers,
        };
        Ok(Self {
            db,
            cfg: opts.bridge,
            run,
            db_path: opts.db_path.clone(),
            bridge,
            cni,
            detach,
            rootless,
            rootless_netns,
            pasta: std::sync::Arc::default(),
            early_pasta: std::sync::Mutex::new(HashMap::new()),
            held: std::sync::Mutex::new(HashMap::new()),
            prepared: std::sync::Mutex::new(std::collections::HashSet::new()),
            monitors: std::sync::Mutex::new(HashMap::new()),
            records: Records::new(&opts.db_path),
        })
    }

    /// Bridge networks can be set up: root where the links are (or the
    /// rootless network namespace, with the pasta it needs).
    pub fn bridge_available(&self) -> bool {
        self.bridge_opts().is_ok()
    }

    /// The options of the bridges, where bridges can be set up: a rootless
    /// engine needs the rootless network namespace, and pasta to connect it
    /// (else the error of `require_pasta`, as for a container's pasta).
    pub(super) fn bridge_opts(&self) -> NetworkResult<&BridgeOptions> {
        if self.rootless {
            if !self.rootless_netns {
                return Err(NetworkError::InvalidConfig(
                    "bridge networks need root, or root in the user namespace of a rootless engine"
                        .into(),
                ));
            }
            pasta::require_pasta()?;
        }
        Ok(&self.bridge)
    }

    /// `rootless_netns::keep` off the async threads: it waits for a release
    /// under way.
    async fn keep_rootless_netns(&self) -> NetworkResult<std::fs::File> {
        let run = self.run.clone();
        Ok(
            tokio::task::spawn_blocking(move || velarx_netkernel::rootless_netns::keep(&run))
                .await
                .map_err(|e| NetworkError::Netlink(e.to_string()))??,
        )
    }

    /// The rootless network namespace, made and connected to the host by
    /// pasta if needed: the process that holds it (`rootless_netns`) and
    /// the pasta live until the namespace is released.
    async fn ensure_rootless_netns(&self) -> NetworkResult<PathBuf> {
        // (a release does not take it away while its pasta is started)
        let _keep = self.keep_rootless_netns().await?;
        let run = self.run.clone();
        let db = self.db_path.clone();
        let pid_file = velarx_netkernel::rootless_netns::pasta_pid_file(&self.run);
        let log_file = self.run.join("rootless-netns.pasta.log");
        let (pf, lf) = (pid_file.clone(), log_file.clone());
        let own_scope = super::rootless_netns::wants_own_scope();
        let started = tokio::task::spawn_blocking(
            move || -> NetworkResult<(PathBuf, Option<Vec<String>>)> {
                std::fs::create_dir_all(&run)?;
                let _lock = bridge::lock_networks(&run)?;
                let (p, started) = super::rootless_netns::start(&run, &db, own_scope)?;
                if started {
                    // (a pasta that runs is on the holder before this one,
                    // or on a namespace that is gone: it is waited for, its
                    // tap device would make the next pasta fail)
                    velarx_netkernel::pasta::stop(&pf, true);
                }
                velarx_netkernel::dnsrec::set_upstream(&run, pasta::PASTA_DNS)?;
                if velarx_netkernel::pasta::is_running(&pf) {
                    return Ok((p, None));
                }
                let prog = pasta::require_pasta()?;
                let as_root = rustix::process::geteuid().is_root();
                let plan = pasta::plan(&prog, &[], None, &[], as_root);
                pasta::start(&plan.argv, &p, &pf, &lf)?;
                Ok((p, Some(plan.argv)))
            },
        )
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))??;
        let (path, argv) = started;
        if let Some(argv) = argv {
            info!("the rootless network namespace is connected by pasta");
            self.pasta
                .watch("rootless-netns", argv, &path, &pid_file, &log_file);
        }
        Ok(path)
    }

    /// Before the monitor of the container `id` is started: the rootless
    /// namespace of its bridge networks, made and connected (a rootless
    /// engine, bridge mode), opened.  The monitor holds the descriptor for
    /// as long as it lives: the namespace then outlives the process that
    /// holds it when that is killed.  None for the other modes.
    pub async fn bridge_netns_for(&self, id: &str) -> NetworkResult<Option<std::os::fd::OwnedFd>> {
        Self::check_id(id)?;
        if !(self.rootless && self.rootless_netns) {
            return Ok(None);
        }
        let Some(spec) = self.spec(id).await? else {
            return Ok(None);
        };
        if spec.mode != Mode::Bridge {
            return Ok(None);
        }
        // (a release does not take the namespace away until it is opened)
        let _keep = self.keep_rootless_netns().await?;
        self.ensure_rootless_netns().await?;
        let run = self.run.clone();
        let db = self.db_path.clone();
        let found = tokio::task::spawn_blocking(move || {
            velarx_netkernel::rootless_netns::locate(&run, &db, velarx_nsid::tree::members)
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))??;
        Ok(found.map(|f| f.ns))
    }

    /// The options to set up bridges with: for a rootless engine, in the
    /// rootless network namespace.
    pub(super) async fn opts(&self) -> NetworkResult<BridgeOptions> {
        let mut o = self.bridge_opts()?.clone();
        if self.rootless {
            o.netns = Some(self.ensure_rootless_netns().await?);
        }
        Ok(o)
    }

    /// Run `check` on a netlink socket where the bridges are: the rootless
    /// network namespace if one lives (kept from a release until `check` is
    /// done; it holds the routes of the host that pasta copied), else the
    /// namespace of the host, where podman checks too.  A check makes no
    /// rootless namespace: no container would be there to release it.
    async fn check_where_bridges(
        &self,
        check: impl FnOnce(&mut velarx_netkernel::netlink::Netlink) -> NetworkResult<()>
            + Send
            + 'static,
    ) -> NetworkResult<()> {
        let rootless = self.rootless && self.rootless_netns;
        let _keep = if rootless {
            Some(self.keep_rootless_netns().await?)
        } else {
            None
        };
        let run = self.run.clone();
        let db = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> NetworkResult<()> {
            let check = move || check(&mut velarx_netkernel::netlink::Netlink::open()?);
            let ns = if rootless {
                velarx_netkernel::rootless_netns::path_in(&run, &db, velarx_nsid::tree::members)?
            } else {
                None
            };
            match ns {
                None => check(),
                Some(p) => {
                    let ns = std::fs::File::open(&p)?;
                    bridge::in_netns(std::os::fd::AsFd::as_fd(&ns), move || Ok(check()))?
                }
            }
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// Refuse a bridge name that is already a link and a subnet that
    /// overlaps an address or a route, where the bridges live.
    pub async fn check_host(&self, bridge: Option<&str>, subnet: &Subnet) -> NetworkResult<()> {
        let (bridge, subnet) = (bridge.map(String::from), *subnet);
        self.check_where_bridges(move |nl| {
            if let Some(bridge) = bridge.filter(|b| nl.link(b).ok().flatten().is_some()) {
                return Err(NetworkError::AlreadyExists(format!(
                    "the interface `{bridge}` exists on the host"
                )));
            }
            bridge::check_subnet_free(nl, &subnet, 0).map_err(overlap_error)
        })
        .await
    }

    /// Whether the interface NAME exists in the namespace of the host.
    pub async fn interface_exists(&self, name: &str) -> NetworkResult<bool> {
        let name = name.to_string();
        tokio::task::spawn_blocking(move || -> NetworkResult<bool> {
            let nl = velarx_netkernel::netlink::Netlink::open()?;
            Ok(nl.link_index(&name)? != 0)
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// The interface of the default route of the host, the parent of a
    /// macvlan network that names none.
    pub async fn default_route_interface(&self) -> NetworkResult<String> {
        tokio::task::spawn_blocking(|| -> NetworkResult<String> {
            let mut nl = velarx_netkernel::netlink::Netlink::open()?;
            let idx = nl.default_route_link()?;
            nl.links()?
                .into_iter()
                .find(|l| idx != 0 && l.index == idx)
                .map(|l| l.name)
                .ok_or_else(|| {
                    NetworkError::InvalidConfig(
                        "no default route: a macvlan network needs a parent interface".into(),
                    )
                })
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// Refuse an IPv6 subnet that a route of the host (or of the rootless
    /// network namespace) overlaps.
    pub async fn check_host6(&self, subnet: &Subnet6) -> NetworkResult<()> {
        let subnet = *subnet;
        self.check_where_bridges(move |nl| {
            bridge::check_subnet6_free(nl, &subnet, 0).map_err(overlap_error)
        })
        .await
    }

    /// The network NAME (or id, or id prefix); the default network for
    /// "", "default", "bridge", "podman" and its own name.
    pub async fn lookup(&self, name: &str) -> NetworkResult<NetworkDef> {
        let builtin = NetworkDef::builtin(&self.cfg)?;
        if is_default_name(name) || name == builtin.name || name == builtin.id {
            return Ok(builtin);
        }
        let r = match self.db.get_network(name).await {
            Ok(r) => r,
            Err(velarx_types::DbError::NotFound(_)) => {
                let all = self.db.list_networks().await?;
                let mut m = all
                    .into_iter()
                    .filter(|n| !name.is_empty() && n.id.starts_with(name));
                match (m.next(), m.next()) {
                    (Some(r), None) => r,
                    _ => return Err(NetworkError::NotFound(name.to_string())),
                }
            }
            Err(e) => return Err(e.into()),
        };
        NetworkDef::from_record(&r)?.ok_or_else(|| {
            NetworkError::InvalidConfig(format!("`{}` is not a bridge network", r.name))
        })
    }

    /// Check what a create asks for and pick the free host ports.  Nothing
    /// is written.
    pub async fn plan(&self, req: &NetRequest) -> NetworkResult<Planned> {
        let bad = |m: &str| Err(NetworkError::InvalidConfig(m.to_string()));
        let (mut mode, mut bridges, pasta_options, implicit) = parse_modes(req)?;
        // The default when nothing is asked: pasta when rootless (as podman,
        // bridges are asked for), the default bridge as root.
        if implicit && self.rootless {
            mode = Mode::Pasta;
        }
        let shareable = req
            .annotations
            .get(SHAREABLE_ANNOTATION)
            .map(String::as_str)
            == Some("true");
        let mut ports = req.ports.clone();
        if !ports.is_empty() && !matches!(mode, Mode::Pasta | Mode::Bridge | Mode::Cni) {
            return bad("port mappings need the pasta, a bridge or a CNI network mode");
        }
        let cni = if mode == Mode::Cni {
            bridges.first().map(|b| b.0.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        if mode == Mode::Cni {
            if self.rootless {
                return bad("CNI networks need a daemon running as root");
            }
            for r in &req.cni_ip_ranges {
                if !is_cidr(r) {
                    return bad(&format!("invalid pod CIDR `{r}`"));
                }
            }
            let (cfg, name) = (self.cni.clone(), cni.clone());
            let pod = |k: &str| req.annotations.get(k).cloned().unwrap_or_default();
            let asks = velarx_netkernel::cni::Attachment {
                pod_name: pod("io.kubernetes.pod.name"),
                pod_namespace: pod("io.kubernetes.pod.namespace"),
                pod_uid: pod("io.kubernetes.pod.uid"),
                annotations: req
                    .cni_annotations
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
                ..Default::default()
            };
            tokio::task::spawn_blocking(move || {
                let net = velarx_netkernel::cni::load(
                    &cfg,
                    Some(name.as_str()).filter(|n| !n.is_empty()),
                )?;
                velarx_netkernel::cni::check_requests(&net, &asks)
            })
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?
            .map_err(|e| NetworkError::InvalidConfig(e.to_string()))?;
            if shareable {
                return bad("a shareable network namespace needs bridge networks");
            }
        }
        let mac = match req.mac.as_deref().filter(|m| !m.is_empty()) {
            Some(m) => {
                let mac = addr::parse_mac(m).ok_or_else(|| {
                    NetworkError::InvalidConfig(format!("invalid MAC address `{m}`"))
                })?;
                if !matches!(mode, Mode::Pasta | Mode::Bridge) {
                    return bad("a MAC address needs the pasta or a bridge network mode");
                }
                Some(addr::format_mac(&mac))
            }
            None => None,
        };
        let ip = match req.ip.as_deref().filter(|i| !i.is_empty()) {
            Some(i) => {
                if mode != Mode::Bridge {
                    return bad("a static address needs a bridge network");
                }
                Some(i.parse::<Ipv4Addr>().map_err(|_| {
                    NetworkError::InvalidConfig(format!("invalid IPv4 address `{i}`"))
                })?)
            }
            None => None,
        };
        let ip6 = match req.ip6.as_deref().filter(|i| !i.is_empty()) {
            Some(i) => {
                if mode != Mode::Bridge {
                    return bad("a static address needs a bridge network");
                }
                Some(i.parse::<Ipv6Addr>().map_err(|_| {
                    NetworkError::InvalidConfig(format!("invalid IPv6 address `{i}`"))
                })?)
            }
            None => None,
        };
        if mode == Mode::Bridge {
            if bridges.len() > 1 && (ip.is_some() || ip6.is_some() || mac.is_some()) {
                return bad(
                    "--ip, --ip6 and --mac-address can only be set for a single network: give \
                     each network its own with `--network NAME:ip=ADDRESS,mac=ADDRESS`",
                );
            }
            // (the addresses of the request are those of the first network)
            if let Some((_, first)) = bridges.first_mut() {
                if let Some(ip) = ip {
                    set_once(&mut first.ip, "ip", ip)?;
                }
                if let Some(ip6) = ip6 {
                    set_once(&mut first.ip6, "ip6", ip6)?;
                }
                if mac.is_some() && first.mac.is_some() {
                    return bad("the network option `mac` is given more than once");
                }
            }
        }
        if shareable {
            if mode != Mode::Bridge {
                return bad("a shareable network namespace needs bridge networks");
            }
            if !ports.is_empty() {
                return bad("a shareable network namespace cannot publish ports");
            }
            if bridges
                .iter()
                .any(|(_, o)| o.ip.is_some() || o.ip6.is_some())
            {
                return bad("a shareable network namespace cannot have a static address");
            }
            if mac.is_some() || bridges.iter().any(|(_, o)| o.mac.is_some()) {
                return bad("a shareable network namespace cannot have a static MAC address");
            }
            if bridges.iter().any(|(_, o)| o.ifname.is_some()) {
                return bad("a shareable network namespace cannot name its interfaces");
            }
        }
        if mode == Mode::Pasta {
            pasta::check_options(&pasta_options).map_err(NetworkError::InvalidConfig)?;
            pasta::require_pasta()?;
        }
        let mut nets = Vec::new();
        let mut options = Vec::new();
        let mut names = Vec::new();
        if mode == Mode::Bridge {
            self.bridge_opts()?;
            for (name, o) in bridges {
                let n = self.lookup(&name).await?;
                if nets.iter().any(|o: &NetworkDef| o.id == n.id) {
                    // (the options of one network are given once)
                    if o != NetOptions::default() {
                        return Err(NetworkError::InvalidConfig(format!(
                            "the network `{}` is given more than once",
                            n.name
                        )));
                    }
                    continue;
                }
                nets.push(n);
                options.push(o);
            }
            names = ifnames(&options)?;
            if nets.iter().any(|n| n.macvlan.is_some()) {
                if self.rootless {
                    return bad("macvlan networks need root");
                }
                if shareable {
                    return bad("a shareable network namespace cannot be on a macvlan network");
                }
                if !ports.is_empty() {
                    return bad("ports cannot be published on a macvlan network");
                }
            }
            if shareable && nets.iter().any(|n| n.subnet6.is_some()) {
                return bad("a shareable network namespace needs IPv4-only networks");
            }
            for (n, o) in nets.iter().zip(&options) {
                if let Some(ip) = o.ip6 {
                    check_static_ip6(n, ip)?;
                }
                if let Some(ip) = o.ip {
                    check_static_ip(n, ip)?;
                }
            }
        }
        for p in &ports {
            if p.proto == addr::Proto::Sctp {
                return Err(NetworkError::UnsupportedProtocol(
                    p.proto.as_str().to_string(),
                ));
            }
            if mode == Mode::Bridge
                && matches!(p.host_ip, Some(IpAddr::V6(_)))
                && !nets.first().is_some_and(|n| n.subnet6.is_some())
            {
                return Err(NetworkError::InvalidConfig(format!(
                    "a port published on an IPv6 address needs an IPv6 network: `{p}`"
                )));
            }
        }
        let auto_ports: Vec<usize> = ports
            .iter()
            .enumerate()
            .filter(|(_, p)| p.host_port == 0)
            .map(|(i, _)| i)
            .collect();
        addr::resolve_free_ports(&mut ports)?;

        let mut aliases = Vec::new();
        if !req.name.is_empty() {
            aliases.push(req.name.clone());
        }
        if !req.aliases.is_empty() && matches!(mode, Mode::Pasta | Mode::Host | Mode::None) {
            return Err(NetworkError::InvalidConfig(
                "networks and static ip/mac address can only be used with Bridge mode networking"
                    .into(),
            ));
        }
        aliases.extend(req.aliases.iter().filter(|a| !a.is_empty()).cloned());
        if mode == Mode::Bridge {
            for a in req.implicit_aliases.iter().filter(|a| !a.is_empty()) {
                if !aliases.contains(a) {
                    aliases.push(a.clone());
                }
            }
        }

        let etc = match mode {
            Mode::Bridge => {
                let dns: Vec<String> = nets
                    .iter()
                    .filter(|n| n.dns)
                    .map(|n| n.gateway.to_string())
                    .collect();
                EtcInfo {
                    search: if dns.is_empty() {
                        Vec::new()
                    } else {
                        vec![DNS_SEARCH.to_string()]
                    },
                    keep_host_servers: dns.is_empty(),
                    ipv6: nets.iter().any(|n| n.subnet6.is_some()),
                    nameservers: match dns.is_empty() {
                        false => dns,
                        // Rootless: the loopback of the host is the forwarder
                        // of pasta from the rootless namespace.
                        true if self.rootless => vec![pasta::PASTA_DNS.to_string()],
                        true => Vec::new(),
                    },
                    host_address: if self.rootless {
                        Some(pasta::PASTA_HOST.to_string())
                    } else {
                        nets.first().map(|n| n.gateway.to_string())
                    },
                    address: None,
                }
            }
            Mode::Pasta => {
                let p = pasta::require_pasta()?;
                // (the options of the user: their `--dns-forward` is the
                // name server, their `--map-guest-addr` the host)
                let plan = pasta::plan(&p, &[], None, &pasta_options, false);
                EtcInfo {
                    nameservers: vec![plan.nameserver],
                    keep_host_servers: true,
                    host_address: Some(plan.host_address),
                    address: pasta_address(&pasta_options).map(|a| a.to_string()),
                    ..EtcInfo::default()
                }
            }
            // `container:`, `ns:`, `cni:`: the host's resolvers.
            Mode::Other | Mode::Cni => EtcInfo {
                keep_host_servers: true,
                ..EtcInfo::default()
            },
            _ => EtcInfo {
                keep_host_servers: true,
                ..EtcInfo::default()
            },
        };
        Ok(Planned {
            spec: NetSpec {
                mode,
                name: req.name.clone(),
                ports: ports.iter().map(|p| p.to_string()).collect(),
                mac,
                macs: nets
                    .iter()
                    .zip(&options)
                    .filter_map(|(n, o)| Some((n.id.clone(), addr::format_mac(&o.mac?))))
                    .collect(),
                ifnames: nets
                    .iter()
                    .zip(names)
                    .enumerate()
                    .filter(|(idx, (_, name))| *name != format!("eth{idx}"))
                    .map(|(_, (n, name))| (n.id.clone(), name))
                    .collect(),
                shareable,
                pasta_options,
                cni,
                cni_pod: req
                    .annotations
                    .iter()
                    .filter(|(k, _)| CNI_POD_KEYS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                cni_annotations: if mode == Mode::Cni {
                    req.cni_annotations.clone()
                } else {
                    BTreeMap::new()
                },
                cni_ip_ranges: if mode == Mode::Cni {
                    req.cni_ip_ranges.clone()
                } else {
                    Vec::new()
                },
            },
            nets,
            options,
            aliases,
            etc,
            auto_ports,
        })
    }

    /// Record the host ports picked for the container, each for one
    /// container: a port another created container has since been given
    /// (the picks of two creates at once can be the same: the socket that
    /// found it is closed) is picked again.
    async fn reserve_host_ports(
        &self,
        id: &str,
        spec: &mut NetSpec,
        auto: &[usize],
    ) -> NetworkResult<()> {
        const TRIES: usize = 64;
        let mut ports = spec.port_specs()?;
        for attempt in 1..=TRIES {
            let wanted: Vec<(String, String, u16)> = auto
                .iter()
                .flat_map(|i| {
                    let p = &ports[*i];
                    (0..p.range).map(move |k| {
                        (
                            p.host_ip.map(|a| a.to_string()).unwrap_or_default(),
                            p.proto.as_str().to_string(),
                            p.host_port + k,
                        )
                    })
                })
                .collect();
            match self.db.net_reserve_host_ports(id, &wanted).await {
                Ok(()) => {
                    spec.ports = ports.iter().map(|p| p.to_string()).collect();
                    return Ok(());
                }
                Err(velarx_types::DbError::AlreadyExists(_)) if attempt < TRIES => {
                    let mut again: Vec<PortSpec> = auto
                        .iter()
                        .map(|i| PortSpec {
                            host_port: 0,
                            ..ports[*i].clone()
                        })
                        .collect();
                    addr::resolve_free_ports(&mut again)?;
                    for (i, p) in auto.iter().zip(again) {
                        ports[*i] = p;
                    }
                }
                Err(velarx_types::DbError::AlreadyExists(m)) => {
                    return Err(NetworkError::InvalidConfig(m))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Record the plan of the container ID: its settings and its addresses.
    /// The addresses on the first network are returned (none without
    /// one), for /etc/hosts.
    pub async fn commit(&self, id: &str, p: &Planned) -> NetworkResult<Vec<IpAddr>> {
        let mut planned = p.spec.clone();
        if !p.auto_ports.is_empty() {
            self.reserve_host_ports(id, &mut planned, &p.auto_ports)
                .await?;
        }
        let spec = serde_json::to_string(&planned)
            .map_err(|e| NetworkError::InvalidConfig(e.to_string()))?;
        self.db.net_set_container_spec(id, &spec).await?;
        let mut first = Vec::new();
        for (idx, (n, o)) in p.nets.iter().zip(&p.options).enumerate() {
            let mut aliases = p.aliases.clone();
            aliases.extend(o.aliases.iter().cloned());
            let (ip, ip6) = self
                .db
                .net_attach(id, &n.id, idx as u32, &aliases, choice(n, o.ip, o.ip6))
                .await
                .map_err(|e| match e {
                    velarx_types::DbError::AlreadyExists(m) => {
                        NetworkError::InvalidConfig(format!("network `{}`: {m}", n.name))
                    }
                    // (removed since the container resolved it)
                    velarx_types::DbError::NotFound(_) => NetworkError::NotFound(n.name.clone()),
                    e => e.into(),
                })?;
            if idx == 0 {
                first.push(IpAddr::V4(ip));
                first.extend(ip6.map(IpAddr::V6));
            }
        }
        Ok(first)
    }

    pub async fn spec(&self, id: &str) -> NetworkResult<Option<NetSpec>> {
        self.db
            .net_container_spec(id)
            .await?
            .map(|s| parse_spec(id, &s))
            .transpose()
    }

    /// The setup [`Self::spec`] gives of each of `ids` that has one, in one
    /// query; one that cannot be read has the message of the error (the
    /// others are not refused for it).
    pub async fn specs(&self, ids: &[String]) -> NetworkResult<HashMap<String, SpecRead>> {
        Ok(self
            .db
            .net_container_specs(ids)
            .await?
            .into_iter()
            .map(|(id, s)| {
                let spec = parse_spec(&id, &s).map_err(|e| match e {
                    NetworkError::Unreadable(message) => message,
                    e => e.to_string(),
                });
                (id, spec)
            })
            .collect())
    }

    /// The interfaces of the container on its bridge networks.
    pub async fn interfaces(&self, id: &str) -> NetworkResult<Vec<Interface>> {
        let ids = [id.to_string()];
        let specs = self.specs(&ids).await?;
        if let Some(Err(message)) = specs.get(id) {
            return Err(NetworkError::Unreadable(message.clone()));
        }
        // (a namespace this process holds is looked at, whatever the record
        // says: the container is being started)
        let alive: HashSet<String> = match self.db.get_container(id).await {
            Ok(c) if c.state.is_alive() => ids.iter().cloned().collect(),
            _ => HashSet::new(),
        };
        Ok(self
            .interfaces_of(&ids, &specs, &alive)
            .await?
            .remove(id)
            .unwrap_or_default())
    }

    /// The interfaces of each of `ids` ([`Self::interfaces`]), given the
    /// setups `specs` of them ([`Self::specs`]): the attachments in one
    /// query, each network read once.  A container whose setup cannot be
    /// read has none here (whoever reads the setup finds the error).  Only
    /// the containers of `alive` (the ones whose record says they run) or
    /// that this process holds a namespace for are looked for in their
    /// namespace: a stopped container has none, and the look would cost a
    /// read of the store of the namespaces for each of them.
    pub async fn interfaces_of(
        &self,
        ids: &[String],
        specs: &HashMap<String, SpecRead>,
        alive: &HashSet<String>,
    ) -> NetworkResult<HashMap<String, Vec<Interface>>> {
        let none = NetSpec::default();
        let mut rows = self.db.net_attachments_of_containers(ids).await?;
        let mut networks: HashMap<String, Option<NetworkDef>> = HashMap::new();
        let mut all = HashMap::new();
        for id in ids {
            let spec = match specs.get(id) {
                Some(Ok(spec)) => spec,
                _ => &none,
            };
            let mut out = Vec::new();
            for row in rows.remove(id).unwrap_or_default() {
                if !networks.contains_key(&row.network_id) {
                    let n = self.network_by_id(&row.network_id).await.ok();
                    networks.insert(row.network_id.clone(), n);
                }
                let Some(n) = &networks[&row.network_id] else {
                    continue;
                };
                let mac = match (spec.macs.get(&row.network_id), &spec.mac, row.idx, row.ip) {
                    (Some(m), ..) | (None, Some(m), 0, _) => m.clone(),
                    (_, _, _, Some(ip)) => addr::format_mac(&addr::derive_mac(ip)),
                    _ => String::new(),
                };
                out.push(Interface {
                    network: n.name.clone(),
                    network_id: n.id.clone(),
                    ifname: spec.ifname(&row.network_id, row.idx),
                    ip: row.ip,
                    prefix: n.subnet.prefix,
                    gateway: n.gateway,
                    mac,
                    aliases: row.aliases,
                    ip6: row.ip6,
                    prefix6: n.subnet6.map_or(0, |s| s.prefix),
                    gateway6: n.gateway6,
                    no_gateway: n.internal && !n.dns,
                });
            }
            if out.is_empty()
                && spec.mode == Mode::Pasta
                && (alive.contains(id) || self.held(id).is_some())
            {
                out.extend(self.pasta_interface(id).await);
            }
            if spec.mode == Mode::Cni {
                out.extend(self.cni_interfaces(id));
            }
            all.insert(id.clone(), out);
        }
        Ok(all)
    }

    /// The interface pasta gave the container: the address and the gateway
    /// of the host it copied into the namespace (or the ones asked with
    /// `pasta:--address`).  None when the namespace is gone or has no
    /// address yet.
    async fn pasta_interface(&self, id: &str) -> Option<Interface> {
        let ns = self.live_netns(id).await?.duplicate().ok()?;
        tokio::task::spawn_blocking(move || {
            bridge::in_netns(std::os::fd::AsFd::as_fd(&ns), || {
                let mut nl = velarx_netkernel::netlink::Netlink::open()?;
                let links = nl.links()?;
                let addresses = nl.addresses()?;
                let gateway = nl.default_gateway()?;
                let Some((link, ip, prefix)) =
                    addresses.into_iter().find_map(|(index, ip, prefix)| {
                        let link = links.iter().find(|l| l.index == index)?;
                        (!ip.is_loopback()).then(|| (link.clone(), ip, prefix))
                    })
                else {
                    return Ok(None);
                };
                // the IPv6 address pasta copied from the host, on the same
                // link (none on a host without IPv6: the IPv4 one stays)
                let ip6 = nl
                    .global_addresses6()
                    .unwrap_or_default()
                    .into_iter()
                    .find(|(index, _, _)| *index == link.index);
                let gateway6 = match ip6 {
                    Some(_) => nl.default_gateway6().ok().flatten(),
                    None => None,
                };
                Ok(Some(Interface {
                    network: "pasta".to_string(),
                    network_id: "pasta".to_string(),
                    ifname: link.name,
                    ip: Some(ip),
                    prefix,
                    gateway: gateway.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    mac: link.mac.map(|m| addr::format_mac(&m)).unwrap_or_default(),
                    aliases: Vec::new(),
                    ip6: ip6.map(|(_, a, _)| a),
                    prefix6: ip6.map_or(0, |(_, _, p)| p),
                    gateway6,
                    no_gateway: gateway.is_none(),
                }))
            })
            .ok()
            .flatten()
        })
        .await
        .ok()
        .flatten()
    }

    /// The published ports the monitor of the container holds: those of
    /// bridge networks (pasta binds its own).
    pub async fn held_ports(&self, id: &str) -> NetworkResult<Vec<String>> {
        Ok(match self.spec(id).await? {
            // Rootless, the forwarder holds them.
            // A port on ::1 is the forwarder's (see `setup`).
            Some(s) if s.mode == Mode::Bridge && !self.rootless => s
                .ports
                .into_iter()
                .filter(|p| !p.starts_with("[::1]:"))
                .collect(),
            _ => Vec::new(),
        })
    }

    /// The namespace a `container:ID` or `ns:PATH` mode joins, from the
    /// database (not from what this process remembers: it survives a
    /// restart of the daemon): the one of the target, see `live_netns`.
    /// None for the other modes.
    pub async fn shared_netns(&self, mode: &NetworkMode) -> NetworkResult<Option<Shared>> {
        if let NetworkMode::Ns(path) = mode {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(NetworkError::InvalidConfig(format!(
                    "the network namespace path in `{mode}` must be absolute"
                )));
            }
            if !path.exists() {
                return Err(NetworkError::Missing(format!(
                    "no network namespace at {}",
                    path.display()
                )));
            }
            return Ok(Some(Shared::Path(path)));
        }
        let NetworkMode::Container(target) = mode else {
            return Ok(None);
        };
        let c = self
            .db
            .get_container(target)
            .await
            .map_err(|_| NetworkError::Missing(format!("no such container `{target}`")))?;
        self.live_netns(&c.id)
            .await
            .map(|ns| Some(Shared::Held(ns)))
            .ok_or_else(|| {
                NetworkError::InvalidConfig(format!("the container `{target}` is not running"))
            })
    }

    /// The network namespace of the running container ID, open in this
    /// process: the one this process holds for it, else the one its record
    /// names, opened through a process that lives in it (every process of the
    /// user lives in one user-namespace tree and may open
    /// `/proc/PID/ns/net`) or, for root, from its handle, and checked to be
    /// the recorded one.  A namespace that is held by nothing has none.
    pub async fn live_netns(&self, id: &str) -> Option<Netns> {
        if let Some(ns) = self.held(id) {
            return Some(ns);
        }
        let c = self.db.get_container(id).await.ok()?;
        let pid = c.pid.filter(|_| c.state.is_alive());
        let pids: Vec<i32> = pid.into_iter().collect();
        let records = self.records.clone();
        let who = id.to_string();
        let found = tokio::task::spawn_blocking(move || records.open(&who, &pids))
            .await
            .ok()?;
        // (no record: a container the engine set no network up for)
        found.or_else(|| pid.and_then(|p| Netns::of_process(p).ok()))
    }

    /// The namespace this process holds for the container ID.
    pub fn held(&self, id: &str) -> Option<Netns> {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Hold the namespace NS of the container ID, and record who it is
    /// (with its monitor as a holder, when it is started already: the
    /// runtime made the namespace, in a user namespace of the container's
    /// own, and the monitor opened it after the creation).
    pub(super) fn hold(&self, id: &str, ns: &Netns) {
        match ns.id() {
            Ok(who) => {
                if let Err(e) = self.records.record(id, &who) {
                    warn!("cannot record the network namespace of {id}: {e}");
                }
            }
            Err(e) => warn!("cannot tell which network namespace {id} has: {e}"),
        }
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), ns.clone());
        if let Some(monitor) = self.monitor_of(id) {
            self.add_holder(id, monitor, "monitor");
        }
    }

    /// The monitor of the container ID is process MONITOR (its pid for
    /// good: after it left its parent, see `MonitorConfig::leave_parent`).
    /// It holds the namespace of the container for as long as it lives: it
    /// is recorded as its holder, now if this process holds the namespace
    /// (the monitor inherited it), else when the namespace is recorded
    /// (`hold`, once the runtime made it).
    pub fn monitor_started(&self, id: &str, monitor: i32) {
        self.monitors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), monitor);
        if self.held(id).is_some() {
            self.add_holder(id, monitor, "monitor");
        }
    }

    fn monitor_of(&self, id: &str) -> Option<i32> {
        self.monitors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .copied()
    }

    /// The network of the container ID is set up already: `setup` has
    /// nothing to do.
    /// Whether the network of the container ID was set up before its
    /// creation (`prepare_own`) and waits for `setup`.
    pub fn is_prepared(&self, id: &str) -> bool {
        self.prepared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(id)
    }

    pub(super) fn mark_prepared(&self, id: &str) {
        self.prepared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string());
    }

    /// This process holds no namespace for the container ID any more (its
    /// monitor does, or nobody needs it), and none is prepared.
    pub fn release_held(&self, id: &str) {
        self.prepared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        self.monitors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }

    /// The process `pid` is in the namespace of the container ID, and keeps
    /// it, as `role`.
    pub fn add_holder(&self, id: &str, pid: i32, role: &str) {
        if let Err(e) = self.records.add_holder(id, pid, role) {
            warn!("cannot record the holder of the network namespace of {id}: {e}");
        }
    }

    /// Stop watching the pasta of the container ID (off the async threads:
    /// it waits for the watching thread).  The pasta of a namespace that
    /// ended is no death to repair: a watch that outlived it would start
    /// one for the next run of the container.
    async fn unwatch(&self, id: &str) -> NetworkResult<()> {
        let (supervisor, id) = (self.pasta.clone(), id.to_string());
        tokio::task::spawn_blocking(move || supervisor.unwatch(&id))
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))
    }

    /// Before the runtime creates a container whose network the engine
    /// sets up (pasta, bridge networks, CNI) in a namespace of its own: make
    /// the namespace, hold it, and record it.  The monitor inherits it and
    /// the runtime joins it (`/proc/PID/fd/N` of the monitor).  None for the
    /// other modes (a shareable namespace is `prepare`'s).
    pub async fn prepare_netns(&self, id: &str) -> NetworkResult<Option<Netns>> {
        Self::check_id(id)?;
        let Some(spec) = self.spec(id).await? else {
            return Ok(None);
        };
        match spec.mode {
            Mode::Pasta => {
                pasta::require_pasta()?;
            }
            Mode::Bridge if !spec.shareable => {}
            Mode::Cni => {}
            _ => return Ok(None),
        }
        // (the exit of the last run is recorded, and its network torn down,
        // by the cleanup command of its monitor, another process: the watch
        // this process keeps of that run's pasta ends here)
        self.unwatch(id).await?;
        let ns = tokio::task::spawn_blocking(Netns::create)
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))??;
        self.hold(id, &ns);
        Ok(Some(ns))
    }

    /// Once the monitor of the container ID is started and holds its
    /// namespace as descriptor FD: start pasta in it, while the runtime
    /// creates the container, which joins the namespace; `setup` waits for
    /// it.  (Not before the monitor: it holds the namespace pasta joins.)
    pub async fn start_pasta(&self, id: &str, monitor: u32, fd: i32) -> NetworkResult<()> {
        Self::check_id(id)?;
        let Some(spec) = self.spec(id).await? else {
            return Ok(());
        };
        if spec.mode != Mode::Pasta {
            return Ok(());
        }
        let netns = PathBuf::from(velarx_nsid::path_in(monitor, fd));
        let prog = pasta::require_pasta()?;
        let plan = pasta::plan(
            &prog,
            &spec.port_specs()?,
            spec.mac.as_deref(),
            &spec.pasta_options,
            rustix::process::geteuid().is_root(),
        );
        std::fs::create_dir_all(self.run.join("pasta"))?;
        let (pid_file, log_file) = (self.pasta_file(id, "pid"), self.pasta_file(id, "log"));
        let (argv, ns, pf, lf) = (
            plan.argv.clone(),
            netns.clone(),
            pid_file.clone(),
            log_file.clone(),
        );
        let started = tokio::task::spawn_blocking(move || pasta::start(&argv, &ns, &pf, &lf));
        self.early_pasta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id.to_string(),
                EarlyPasta {
                    started,
                    argv: plan.argv,
                    netns,
                    pid_file,
                    log_file,
                },
            );
        Ok(())
    }

    /// Before the runtime creates a container (or restores a checkpoint of
    /// one: the one of the checkpoint is not in its images) in a namespace of
    /// its own with bridge or CNI networks: make the namespace, set the
    /// networks up in it, hold it.  The container whose network fails is
    /// never created, and when it exits its network is complete.  None for
    /// the other modes (a shareable namespace is `prepare`'s, pasta's
    /// `prepare_netns`).
    pub async fn prepare_own(&self, id: &str) -> NetworkResult<Option<NetworkStatus>> {
        Self::check_id(id)?;
        let Some(spec) = self.spec(id).await? else {
            return Ok(None);
        };
        if !matches!(spec.mode, Mode::Bridge | Mode::Cni) {
            return Ok(None);
        }
        if spec.mode == Mode::Bridge {
            self.opts().await?;
        }
        let Some(ns) = self.prepare_netns(id).await? else {
            return Ok(None);
        };
        let status = self.setup_in(id, &spec, &ns, None).await?;
        self.mark_prepared(id);
        Ok(status)
    }

    /// Set up the networks of the container ID in its network namespace:
    /// the one this process holds for it (`prepare_netns`), else the one of
    /// its process PID (a container in a user namespace of its own, which
    /// the runtime made).  Nothing to do for the modes not handled here
    /// (host, none, `container:`, overlays): `Ok(None)`.
    pub async fn setup(&self, id: &str, pid: Option<i32>) -> NetworkResult<Option<NetworkStatus>> {
        Self::check_id(id)?;
        let Some(spec) = self.spec(id).await? else {
            return Ok(None);
        };
        // The pasta that `start_pasta` started in the namespace the
        // container was created in.
        let early = self
            .early_pasta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(early) = early {
            let started = early
                .started
                .await
                .map_err(|e| NetworkError::Netlink(e.to_string()))?;
            velarx_base::trace::point("network pasta started");
            started?;
            self.pasta.watch(
                id,
                early.argv,
                &early.netns,
                &early.pid_file,
                &early.log_file,
            );
            return Ok(Some(NetworkStatus {
                mode: Mode::Pasta,
                interfaces: Vec::new(),
                prepared: false,
            }));
        }
        // A namespace `prepare` or `prepare_own` set up before the
        // runtime created the container in it.
        let was_prepared = self
            .prepared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if was_prepared {
            if let Some(pid) = pid {
                self.add_holder(id, pid, "container");
            }
            return Ok(Some(NetworkStatus {
                mode: spec.mode,
                interfaces: self.interfaces(id).await?,
                prepared: true,
            }));
        }
        let ns = match self.held(id) {
            Some(ns) => ns,
            None => {
                let pid = pid.ok_or_else(|| {
                    NetworkError::InvalidConfig(format!("no network namespace for {id}"))
                })?;
                let ns = Netns::of_process(pid)?;
                self.hold(id, &ns);
                ns
            }
        };
        if let Some(pid) = pid {
            self.add_holder(id, pid, "container");
        }
        self.setup_in(id, &spec, &ns, pid).await
    }

    /// `setup` in the namespace NS of the container ID, whose process is
    /// PID when it exists.
    pub(super) async fn setup_in(
        &self,
        id: &str,
        spec: &NetSpec,
        ns: &Netns,
        pid: Option<i32>,
    ) -> NetworkResult<Option<NetworkStatus>> {
        match spec.mode {
            Mode::Bridge => {
                // (a release of the namespace waits for the end of the setup)
                let _keep = if self.rootless && self.rootless_netns {
                    Some(self.keep_rootless_netns().await?)
                } else {
                    None
                };
                let opts = self.opts().await?;
                let pin = ns.path();
                self.assign_missing_ips(id).await?;
                let Some(input) = self.bridge_input(id, None).await? else {
                    return Err(NetworkError::InvalidConfig(
                        "the container is not attached to any network".into(),
                    ));
                };
                self.bridge_setup(&opts, &pin, &input).await?;
                // Rootless: the host ports go through a forwarder.
                if let (Some(rootless_ns), false, Some(first)) = (
                    opts.netns.clone(),
                    input.ports.is_empty(),
                    input.attachments.first(),
                ) {
                    std::fs::create_dir_all(self.run.join("portfwd"))?;
                    let (exe, pid_file) = (opts.dns_exe.clone(), self.portfwd_pid(id));
                    let (cid, ip, ports) = (id.to_string(), first.ip, input.ports.clone());
                    let r = tokio::task::spawn_blocking(move || {
                        let ip = IpAddr::V4(ip);
                        super::portfwd::start(&exe, Some(&rootless_ns), &cid, ip, &ports, &pid_file)
                    })
                    .await
                    .map_err(|e| NetworkError::Netlink(e.to_string()))?;
                    if let Err(e) = r {
                        let path = pin.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            bridge::teardown(&opts, Some(&path), &input, NetnsFate::Stays)
                        })
                        .await;
                        return Err(e.into());
                    }
                }
                // Rootful dual stack: the ports published on all the
                // addresses (or on ::1) are on ::1 through a forwarder, as
                // the firewall cannot route the loopback to a bridge.
                let loopback6: Vec<PortSpec> = input
                    .ports
                    .iter()
                    .filter(|p| {
                        p.host_ip
                            .is_none_or(|h| h == IpAddr::V6(Ipv6Addr::LOCALHOST))
                    })
                    .map(|p| PortSpec {
                        host_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                        ..p.clone()
                    })
                    .collect();
                let first6 = input.attachments.first().and_then(|a| a.ip6);
                if let (None, Some(ip6), false) = (&opts.netns, first6, loopback6.is_empty()) {
                    std::fs::create_dir_all(self.run.join("portfwd"))?;
                    let (exe, pid_file) = (opts.dns_exe.clone(), self.portfwd_pid(id));
                    let cid = id.to_string();
                    let r = tokio::task::spawn_blocking(move || {
                        let ip = IpAddr::V6(ip6);
                        super::portfwd::start(&exe, None, &cid, ip, &loopback6, &pid_file)
                    })
                    .await
                    .map_err(|e| NetworkError::Netlink(e.to_string()))?;
                    if let Err(e) = r {
                        let path = pin.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            bridge::teardown(&opts, Some(&path), &input, NetnsFate::Stays)
                        })
                        .await;
                        return Err(e.into());
                    }
                }
                info!("bridge networks of {id} set up");
                Ok(Some(NetworkStatus {
                    mode: Mode::Bridge,
                    interfaces: self.interfaces(id).await?,
                    prepared: false,
                }))
            }
            Mode::Pasta => {
                // (a pasta that ended with its namespace is not to be started
                // again)
                self.unwatch(id).await?;
                // Not started before the runtime: the container has a user
                // namespace of its own, and its namespace is the process's.
                // (a path that lasts as long as the container: its monitor's
                // descriptor, else, a pasta ending with the process of its
                // path, the one of its init)
                let path = self.records.load(id).ok().and_then(|stored| {
                    stored
                        .holders
                        .iter()
                        .filter(|h| h.role == "monitor")
                        .filter(|h| velarx_nsid::start_time(h.pid) == Some(h.start))
                        .find_map(|h| {
                            let at = ns.fd_in(h.pid as u32)?;
                            Some(PathBuf::from(velarx_nsid::path_in(h.pid as u32, at)))
                        })
                });
                let path = match (path, pid) {
                    (Some(path), _) => path,
                    (None, Some(pid)) => PathBuf::from(format!("/proc/{pid}/ns/net")),
                    (None, None) => {
                        return Err(NetworkError::InvalidConfig(format!(
                            "no process for the network of {id}"
                        )))
                    }
                };
                let prog = pasta::require_pasta()?;
                let ports = spec.port_specs()?;
                let as_root = rustix::process::geteuid().is_root();
                let plan = pasta::plan(
                    &prog,
                    &ports,
                    spec.mac.as_deref(),
                    &spec.pasta_options,
                    as_root,
                );
                std::fs::create_dir_all(self.run.join("pasta"))?;
                let (pid_file, log_file) = (self.pasta_file(id, "pid"), self.pasta_file(id, "log"));
                let (argv, ns, pf, lf) = (
                    plan.argv.clone(),
                    path.clone(),
                    pid_file.clone(),
                    log_file.clone(),
                );
                tokio::task::spawn_blocking(move || pasta::start(&argv, &ns, &pf, &lf))
                    .await
                    .map_err(|e| NetworkError::Netlink(e.to_string()))??;
                velarx_base::trace::point("network pasta started");
                self.pasta.watch(id, plan.argv, &path, &pid_file, &log_file);
                Ok(Some(NetworkStatus {
                    mode: Mode::Pasta,
                    interfaces: Vec::new(),
                    prepared: false,
                }))
            }
            Mode::Cni => {
                self.cni_add(id, spec, &ns.path()).await?;
                info!("CNI network of {id} set up");
                Ok(Some(NetworkStatus {
                    mode: Mode::Cni,
                    interfaces: self.interfaces(id).await?,
                    prepared: false,
                }))
            }
            _ => Ok(None),
        }
    }

    /// ADD of the CNI network of the container ID, whose namespace is pinned.
    async fn cni_add(&self, id: &str, spec: &NetSpec, pin: &Path) -> NetworkResult<()> {
        let (cfg, name) = (self.cni.clone(), spec.cni.clone());
        let attachment = cni_attachment(id, spec, Some(pin))?;
        tokio::task::spawn_blocking(move || {
            let net =
                velarx_netkernel::cni::load(&cfg, Some(name.as_str()).filter(|n| !n.is_empty()))?;
            velarx_netkernel::cni::add(&cfg, &net, &attachment)
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
        .map(|_| ())
        .map_err(|e| NetworkError::Cni(e.to_string()))
    }

    /// DEL of the CNI attachments the cache has for containers that do not
    /// run any more (the daemon was down when they stopped, or the host
    /// rebooted); the number released.  An attachment whose namespace is
    /// still recorded is not stale: its container is being made or started
    /// (its record is not `running` yet), or its teardown, which DELs it
    /// with the namespace, is to come; every process of the engine runs
    /// this at its start, while others make containers.
    pub async fn release_stale_cni(&self) -> usize {
        if self.rootless {
            return 0;
        }
        let Ok(containers) = self.db.list_containers(true).await else {
            return 0;
        };
        let running: std::collections::HashSet<String> = containers
            .into_iter()
            .filter(|c| c.state.is_alive())
            .map(|c| c.id)
            .collect();
        let cfg = self.cni.clone();
        let records = self.records.clone();
        let released = tokio::task::spawn_blocking(move || {
            velarx_netkernel::cni::gc(&cfg, &|id| cni_attachment_live(&running, &records, id))
        })
        .await
        .unwrap_or(0);
        if released > 0 {
            info!("released {released} CNI attachments of containers that are gone");
        }
        released
    }

    /// The CNI network NAME (`cni:NAME`, `cni:` for the first configuration)
    /// as the plugins say it is: the configuration, and whether the STATUS
    /// verb of its plugins finds it ready (a configuration of an older
    /// version of CNI is ready when it exists).  A network with no
    /// configuration is not found.
    pub async fn cni_status(&self, name: &str) -> NetworkResult<serde_json::Value> {
        if self.rootless {
            return Err(NetworkError::InvalidConfig(
                "CNI networks need a daemon running as root".into(),
            ));
        }
        let (cfg, name) = (self.cni.clone(), name.to_string());
        tokio::task::spawn_blocking(move || {
            let net = match velarx_netkernel::cni::load(&cfg, Some(name.as_str()).filter(|n| !n.is_empty())) {
                Ok(net) => net,
                Err(velarx_netkernel::cni::CniError::NoConfig(m)) => return Err(NetworkError::NotFound(m)),
                Err(e) => return Err(NetworkError::InvalidConfig(e.to_string())),
            };
            let status = velarx_netkernel::cni::status(&cfg, &net);
            Ok(serde_json::json!({
                "name": net.name,
                "driver": "cni",
                "cniVersion": net.cni_version,
                "file": net.file,
                "plugins": net.plugins.iter().filter_map(|p| p["type"].as_str()).collect::<Vec<_>>(),
                "ready": status.is_ok(),
                "message": status.err().map(|e| e.to_string()).unwrap_or_default(),
            }))
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// The interface of a container on its CNI network, from the result of
    /// the plugins.
    fn cni_interfaces(&self, id: &str) -> Vec<Interface> {
        let a = velarx_netkernel::cni::Attachment {
            container_id: id.to_string(),
            ifname: CNI_IFNAME.to_string(),
            ..Default::default()
        };
        match velarx_netkernel::cni::cached_result(&self.cni, &a) {
            Some((net, Some(result))) => cni_interface(&net.name, &result).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Give a new address to the attachments of ID that gave theirs to a
    /// pooled namespace.
    async fn assign_missing_ips(&self, id: &str) -> NetworkResult<()> {
        for row in self.db.net_attachments_of_container(id).await? {
            if row.ip.is_none() {
                let n = self.network_by_id(&row.network_id).await?;
                self.db
                    .net_reassign(id, &n.id, choice(&n, None, None))
                    .await?;
            }
        }
        Ok(())
    }

    /// Connect the container of `request` to the network NAME: its address,
    /// and the interface when it runs (its namespace is pinned).
    pub async fn connect(
        &self,
        name: &str,
        request: &ConnectRequest<'_>,
    ) -> NetworkResult<Ipv4Addr> {
        let ConnectRequest {
            container_id: id,
            container_name,
            ip,
            ip6,
            mac,
            aliases,
        } = *request;
        Self::check_id(id)?;
        let n = self.lookup(name).await?;
        if n.macvlan.is_some() && self.rootless {
            return Err(NetworkError::InvalidConfig(
                "macvlan networks need root".into(),
            ));
        }
        let mut spec = self.spec(id).await?.unwrap_or_default();
        if !matches!(spec.mode, Mode::Bridge | Mode::None) {
            return Err(NetworkError::InvalidConfig(format!(
                "the container `{container_name}` does not use bridge networks"
            )));
        }
        self.bridge_opts()?;
        let running = self.live_netns(id).await.is_some();
        if running && spec.shareable {
            return Err(NetworkError::InvalidConfig(format!(
                "the container `{container_name}` has a shareable network namespace, stop it first"
            )));
        }
        let rows = self.db.net_attachments_of_container(id).await?;
        if let Some(r) = rows.iter().find(|r| r.network_id == n.id) {
            // As podman: nothing to do for a container that does not run,
            // refused for one that runs.
            return match running {
                false => Ok(r.ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                true => Err(NetworkError::AlreadyConnected),
            };
        }
        if running && spec.mode != Mode::Bridge {
            return Err(NetworkError::InvalidConfig(format!(
                "the container `{container_name}` runs without bridge networks, stop it first"
            )));
        }
        let idx = rows.iter().map(|r| r.idx + 1).max().unwrap_or(0);
        // (`eth<idx>`, else the first `ethN` the other networks do not have)
        let taken: Vec<String> = rows
            .iter()
            .map(|r| spec.ifname(&r.network_id, r.idx))
            .collect();
        let mut ifname = format!("eth{idx}");
        if taken.contains(&ifname) {
            ifname = free_ifname(taken.iter().map(String::as_str));
        }
        if let Some(ip) = ip {
            check_static_ip(&n, ip)?;
        }
        if let Some(ip) = ip6 {
            check_static_ip6(&n, ip)?;
        }
        let mac = mac.map(|m| addr::format_mac(&m));
        let mut all = Vec::new();
        if !container_name.is_empty() {
            all.push(container_name.to_string());
        }
        all.extend(aliases.iter().filter(|a| !a.is_empty()).cloned());
        // (its short id is a name on this network too, as at its creation:
        // podman's getExtraNetworkAliases)
        let short: String = id.chars().take(12).collect();
        if !all.contains(&short) {
            all.push(short);
        }
        let got = self
            .db
            .net_attach(id, &n.id, idx, &all, choice(&n, ip, ip6))
            .await
            .map_err(|e| match e {
                velarx_types::DbError::AlreadyExists(m) => {
                    NetworkError::InvalidConfig(format!("network `{}`: {m}", n.name))
                }
                // (removed since the container resolved it)
                velarx_types::DbError::NotFound(_) => NetworkError::NotFound(n.name.clone()),
                e => e.into(),
            })?;
        let stored = spec.clone();
        let mut changed = mac.map(|m| spec.macs.insert(n.id.clone(), m)).is_some();
        if ifname != format!("eth{idx}") {
            changed = true;
            spec.ifnames.insert(n.id.clone(), ifname);
        }
        if spec.mode == Mode::None {
            changed = true;
            spec.mode = Mode::Bridge;
            if spec.name.is_empty() {
                spec.name = container_name.to_string();
            }
        }
        if changed {
            let s = serde_json::to_string(&spec)
                .map_err(|e| NetworkError::InvalidConfig(e.to_string()))?;
            self.db.net_set_container_spec(id, &s).await?;
        }
        if running {
            if let Err(e) = self.hot_plug(id, &n.id, true).await {
                // (what was set up of the interface goes too)
                let _ = self.hot_plug(id, &n.id, false).await;
                let _ = self.db.net_detach(id, &n.id).await;
                if changed {
                    if let Ok(s) = serde_json::to_string(&stored) {
                        let _ = self.db.net_set_container_spec(id, &s).await;
                    }
                }
                return Err(e);
            }
        }
        Ok(got.0)
    }

    /// Disconnect the container ID from the network NAME; with FORCE the
    /// attachment goes even if the interface cannot be removed.
    pub async fn disconnect(
        &self,
        id: &str,
        name: &str,
        force: bool,
        container_name: &str,
    ) -> NetworkResult<()> {
        Self::check_id(id)?;
        let n = self.lookup(name).await?;
        let spec = self.spec(id).await?.unwrap_or_default();
        let live = self.live_netns(id).await;
        let rows = self.db.net_attachments_of_container(id).await?;
        let attached = rows.iter().any(|r| r.network_id == n.id);
        if !attached {
            return Err(NetworkError::Missing(format!(
                "the container `{container_name}` is not connected to `{}`",
                n.name
            )));
        }
        if live.is_some() && spec.mode == Mode::Bridge {
            // The published ports go to the address of the first network:
            // they would point to an address given back to the network.
            if !spec.ports.is_empty() && rows.first().is_some_and(|r| r.network_id == n.id) {
                return Err(NetworkError::InvalidConfig(format!(
                    "the container `{container_name}` publishes its ports on `{}`, stop it first",
                    n.name
                )));
            }
            if spec.shareable {
                return Err(NetworkError::InvalidConfig(format!(
                    "the container `{container_name}` has a shareable network namespace, stop it first"
                )));
            }
            if let Err(e) = self.hot_plug(id, &n.id, false).await {
                if !force {
                    return Err(e);
                }
            }
        }
        self.db.net_detach(id, &n.id).await?;
        let mut spec = spec;
        let last = rows.len() == 1 && spec.mode == Mode::Bridge;
        if last {
            // (nothing to set up at the next start: the loopback only)
            spec.mode = Mode::None;
        }
        let named = spec.macs.remove(&n.id).is_some() | spec.ifnames.remove(&n.id).is_some();
        if named || last {
            let s = serde_json::to_string(&spec)
                .map_err(|e| NetworkError::InvalidConfig(e.to_string()))?;
            self.db.net_set_container_spec(id, &s).await?;
        }
        Ok(())
    }

    /// Apply the firewall rules of the bridge networks of the running
    /// container ID again.  False: it has no bridge network to do it for.
    pub async fn reload(&self, id: &str) -> NetworkResult<bool> {
        Self::check_id(id)?;
        let spec = self.spec(id).await?.unwrap_or_default();
        if spec.mode != Mode::Bridge || self.live_netns(id).await.is_none() {
            return Ok(false);
        }
        let Some(input) = self.bridge_input(id, None).await? else {
            return Ok(false);
        };
        let opts = self.opts().await?;
        tokio::task::spawn_blocking(move || bridge::reload(&opts, &input))
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))??;
        Ok(true)
    }

    /// Set up or tear down one network of a running container.
    async fn hot_plug(&self, id: &str, network_id: &str, up: bool) -> NetworkResult<()> {
        // (a release of the namespace waits for the end of the change)
        let _keep = if self.rootless && self.rootless_netns {
            Some(self.keep_rootless_netns().await?)
        } else {
            None
        };
        let opts = self.opts().await?;
        let Some(input) = self.bridge_input(id, Some(network_id)).await? else {
            return Ok(());
        };
        let Some(ns) = self.live_netns(id).await else {
            return Err(NetworkError::InvalidConfig(format!(
                "the container {id} is not running"
            )));
        };
        if up {
            return self.bridge_setup(&opts, &ns.path(), &input).await;
        }
        tokio::task::spawn_blocking(move || {
            bridge::teardown(&opts, Some(&ns.path()), &input, NetnsFate::Stays)
        })
        .await
        .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// `bridge::setup` off the async threads.
    async fn bridge_setup(
        &self,
        opts: &BridgeOptions,
        pin: &Path,
        input: &bridge::BridgeContainer,
    ) -> NetworkResult<()> {
        let (o, p, i) = (opts.clone(), pin.to_path_buf(), input.clone());
        tokio::task::spawn_blocking(move || bridge::setup(&o, &p, &i))
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// The network N goes: its pooled namespaces, its bridge, rules, DNS
    /// records and attachments.
    pub async fn network_removed(&self, n: &NetworkDef) -> NetworkResult<()> {
        let def = n.net_def();
        self.network_gone(&n.id, &n.name, move |opts| {
            bridge::network_remove(opts, &def)
        })
        .await
    }

    /// The network ID (NAME), whose record could not be read, goes: what its
    /// bridge (the one with its owner mark) was set up with is read from
    /// the bridge.
    pub async fn network_removed_by_mark(&self, id: &str, name: &str) -> NetworkResult<()> {
        let mark = id.to_string();
        self.network_gone(id, name, move |opts| {
            bridge::network_remove_by_mark(opts, &mark)
        })
        .await
    }

    /// The network ID (NAME) goes: its pooled namespaces, what REMOVE takes
    /// down where the bridges are, its attachments.
    async fn network_gone(
        &self,
        id: &str,
        name: &str,
        remove: impl FnOnce(&BridgeOptions) -> NetworkResult<()> + Send + 'static,
    ) -> NetworkResult<()> {
        self.pool_drain(Some(id)).await?;
        let removed = match self.opts_if_any()? {
            Some(opts) => tokio::task::spawn_blocking(move || remove(&opts))
                .await
                .map_err(|e| NetworkError::Netlink(e.to_string()))?
                .map_err(|e| NetworkError::Netlink(format!("remove the network {name}: {e}"))),
            None => Ok(()),
        };
        self.release_rootless_netns_if_unused().await;
        self.db.net_forget_network(id).await?;
        removed
    }

    /// The DNS servers of N changed: the running containers use them.
    pub async fn network_dns_updated(&self, n: &NetworkDef) -> NetworkResult<()> {
        if !n.dns || !self.bridge_available() {
            return Ok(());
        }
        let Some(opts) = self.opts_if_any()? else {
            return Ok(());
        };
        let def = n.net_def();
        tokio::task::spawn_blocking(move || bridge::network_dns_update(&opts, &def))
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?
    }

    /// The containers on the network: (container id, address).
    pub async fn members(
        &self,
        network_id: &str,
    ) -> NetworkResult<Vec<(String, Option<Ipv4Addr>)>> {
        Ok(self
            .db
            .net_attachments_of_network(network_id)
            .await?
            .into_iter()
            .map(|r| (r.container_id, r.ip))
            .collect())
    }
}

/// Whether the CNI attachment of the container ID may be in use: its
/// container runs, or its namespace is pinned in PINS (it is being made or
/// started, or its teardown is to come).
fn cni_attachment_live(
    running: &std::collections::HashSet<String>,
    records: &Records,
    id: &str,
) -> bool {
    running.contains(id) || records.exists(id)
}

/// The addresses the IPAM may give.
pub(super) fn choice(
    n: &NetworkDef,
    requested: Option<Ipv4Addr>,
    requested6: Option<Ipv6Addr>,
) -> IpChoice {
    let (mut first, mut last) = (n.subnet.network() + 1, n.subnet.broadcast() - 1);
    if let Some((a, b)) = n.ip_range {
        first = first.max(u32::from(a));
        last = last.min(u32::from(b));
    }
    IpChoice {
        registered: !n.builtin,
        requested,
        first: Ipv4Addr::from(first),
        last: Ipv4Addr::from(last),
        excluded: vec![n.gateway],
        v6: match (n.subnet6, n.gateway6) {
            (Some(s), Some(gw)) => Some(Ip6Choice {
                requested: requested6,
                first: Ipv6Addr::from(s.network() + 1),
                last: s.last(),
                excluded: vec![gw],
            }),
            _ => None,
        },
    }
}

impl ContainerNetworks {
    /// Run `f` on a thread that may block, with the database as a
    /// connection of the sync code and what releases a network.
    pub(super) async fn blocking<R: Send + 'static>(
        &self,
        f: impl FnOnce(&BlockingDb<'_>, &Detach) -> R + Send + 'static,
    ) -> NetworkResult<R> {
        let (db, detach) = (self.db.clone(), self.detach.clone());
        tokio::task::spawn_blocking(move || f(&BlockingDb::new(&db), &detach))
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))
    }

    /// What the release of the network of a container needs: the engine
    /// builds it once, the plan of the monitor of a container carries it.
    pub fn detach(&self) -> &Detach {
        &self.detach
    }

    fn portfwd_pid(&self, id: &str) -> PathBuf {
        self.detach.portfwd_pid(id)
    }

    fn pasta_file(&self, id: &str, ext: &str) -> PathBuf {
        self.detach.pasta_file(id, ext)
    }

    fn check_id(id: &str) -> NetworkResult<()> {
        check_id(id)
    }

    pub(super) fn opts_if_any(&self) -> NetworkResult<Option<BridgeOptions>> {
        self.detach.opts_if_any()
    }

    pub(super) async fn network_by_id(&self, id: &str) -> NetworkResult<NetworkDef> {
        let id = id.to_string();
        self.blocking(move |db, d| velarx_netdetach::input::network_by_id(db, &d.cfg, &id))
            .await?
    }

    /// The input of the bridge setup of the container: all its networks, or
    /// ONLY one (connect/disconnect: without the published ports).
    pub(super) async fn bridge_input(
        &self,
        id: &str,
        only: Option<&str>,
    ) -> NetworkResult<Option<BridgeContainer>> {
        let (id, only) = (id.to_string(), only.map(String::from));
        self.blocking(move |db, d| {
            velarx_netdetach::input::bridge_input(db, &d.cfg, &id, only.as_deref())
        })
        .await?
    }

    /// Give the rootless network namespace and its pasta up when no bridge
    /// in it has a port (see `Detach::release_if_unused`).
    pub async fn release_rootless_netns_if_unused(&self) {
        let supervisor = self.pasta.clone();
        let _ = self
            .blocking(move |_, d| d.release_if_unused(&|| supervisor.unwatch("rootless-netns")))
            .await;
    }

    /// Undo `setup` once the container stopped: stop pasta, tear the bridge
    /// networks down (or give the namespace to the pool), forget the
    /// namespace, stop the providers.  Best effort.  The namespace is the one
    /// this process holds for the container, else the one its record names;
    /// the kernel destroys it with the last descriptor and process.  The
    /// monitor of the container runs the same release (`Detach`) itself when
    /// the container ends; this is for the paths where no monitor is.
    pub async fn teardown(&self, id: &str) -> NetworkResult<()> {
        Self::check_id(id)?;
        // (it may wait for a pasta being started: off the async threads)
        let _ = self.unwatch(id).await;
        // A pasta started for a container that was not created: it is
        // waited for, to be stopped like the others.
        let early = self
            .early_pasta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(early) = early {
            let _ = early.started.await;
        }
        self.prepared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        let held = self.live_netns(id).await;
        let (owned, supervisor) = (id.to_string(), self.pasta.clone());
        let done = self
            .blocking(move |db, d| {
                d.release(db, &owned, held, &|| supervisor.unwatch("rootless-netns"))
            })
            .await?;
        self.release_held(id);
        done.map(|_| ())
    }

    /// Tear down the pooled namespaces of the network NETWORK_ID (all of
    /// them when None).
    pub async fn pool_drain(&self, network_id: Option<&str>) -> NetworkResult<()> {
        let net = network_id.map(String::from);
        self.blocking(move |db, d| d.pool_drain(db, net.as_deref()))
            .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_db::NetworkRecord;

    #[test]
    fn a_connect_request_is_parsed_where_the_words_are() {
        let aliases = ["a".to_string()];
        let ask = |ip, ip6, mac| ConnectRequest::parse(("c", "n"), ip, ip6, mac, &aliases);
        let r = ask(
            Some("10.89.0.5"),
            Some("fd00::5"),
            Some("02:42:0a:58:07:05"),
        )
        .unwrap();
        assert_eq!(r.ip, Some(Ipv4Addr::new(10, 89, 0, 5)));
        assert_eq!(r.ip6, Some("fd00::5".parse().unwrap()));
        assert_eq!(r.mac, Some([2, 0x42, 10, 0x58, 7, 5]));
        let r = ask(Some(""), None, Some("")).unwrap();
        assert!(r.ip.is_none() && r.ip6.is_none() && r.mac.is_none());
        let why = |e: Result<ConnectRequest, NetworkError>| e.err().unwrap().to_string();
        assert!(why(ask(Some("nope"), None, None)).contains("invalid IPv4 address `nope`"));
        assert!(why(ask(None, Some("1.2.3.4"), None)).contains("invalid IPv6 address"));
        assert!(why(ask(None, None, Some("x"))).contains("invalid MAC address"));
    }

    #[test]
    fn an_attachment_with_a_namespace_is_not_stale() {
        let dir = tempfile::tempdir().unwrap();
        let records = Records::new(&dir.path().join("db.sqlite"));
        let mine = velarx_nsid::own(velarx_nsid::Kind::Net).unwrap();
        records.record("starting", &mine).unwrap();
        let running: std::collections::HashSet<String> = ["up".to_string()].into();
        assert!(cni_attachment_live(&running, &records, "up"));
        // (made, its record not running yet: another process's GC leaves it)
        assert!(cni_attachment_live(&running, &records, "starting"));
        assert!(!cni_attachment_live(&running, &records, "gone"));
        records.forget("starting").unwrap();
        assert!(!cni_attachment_live(&running, &records, "starting"));
    }

    /// A container disconnected from its only network has none left: it
    /// starts with the loopback only, as podman's.
    #[tokio::test]
    async fn a_container_disconnected_from_its_last_network_has_no_network() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let record = NetworkRecord {
            id: "n1".repeat(32),
            name: "n1".into(),
            driver: "bridge".into(),
            subnet: Some("10.213.60.0/24".into()),
            gateway: None,
            options: None,
            created_at: "now".into(),
            subnet6: None,
            gateway6: None,
        };
        db.insert_network(&record).await.unwrap();
        let nets = ContainerNetworks::new(
            db.clone(),
            EngineOptions {
                state_dir: dir.path().to_path_buf(),
                db_path: dir.path().join("db.sqlite"),
                bridge: BridgeConfig::default(),
                table: "t".into(),
                dns_exe: "velarx".into(),
                cni: velarx_config::CniConfig::default(),
                providers: Vec::new(),
            },
        )
        .unwrap();
        let def = nets.lookup("n1").await.unwrap();
        let spec = NetSpec {
            mode: Mode::Bridge,
            ..Default::default()
        };
        db.net_set_container_spec("c1", &serde_json::to_string(&spec).unwrap())
            .await
            .unwrap();
        db.net_attach("c1", &def.id, 0, &["c1".into()], choice(&def, None, None))
            .await
            .unwrap();
        nets.disconnect("c1", "n1", false, "c1").await.unwrap();
        assert!(db
            .net_attachments_of_container("c1")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(nets.spec("c1").await.unwrap().unwrap().mode, Mode::None);
    }

    /// A port the pick of another container has recorded is picked again:
    /// two creates at once never publish the same host port.
    #[tokio::test]
    async fn a_host_port_of_another_container_is_picked_again() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now'), ('c2','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let nets = ContainerNetworks::new(
            db.clone(),
            EngineOptions {
                state_dir: dir.path().to_path_buf(),
                db_path: dir.path().join("db.sqlite"),
                bridge: BridgeConfig::default(),
                table: "t".into(),
                dns_exe: "velarx".into(),
                cni: velarx_config::CniConfig::default(),
                providers: Vec::new(),
            },
        )
        .unwrap();
        let mut first = addr::PortSpec::single("", None, 80, "tcp").unwrap();
        addr::resolve_free_ports(std::slice::from_mut(&mut first)).unwrap();
        let spec = |p: &addr::PortSpec| NetSpec {
            ports: vec![p.to_string()],
            ..Default::default()
        };
        let mut one = spec(&first);
        nets.reserve_host_ports("c1", &mut one, &[0]).await.unwrap();
        assert_eq!(one.ports, [first.to_string()], "the port picked is kept");
        // the same pick for another container
        let mut two = spec(&first);
        nets.reserve_host_ports("c2", &mut two, &[0]).await.unwrap();
        assert_ne!(two.ports, one.ports);
        let again = two.port_specs().unwrap();
        assert_ne!(again[0].host_port, first.host_port);
        assert_eq!(again[0].container_port, 80);
        // a removed container gives its port back
        db.delete_container("c1").await.unwrap();
        let mut three = spec(&first);
        nets.reserve_host_ports("c2", &mut three, &[0])
            .await
            .unwrap();
        assert_eq!(three.ports, [first.to_string()]);
    }

    /// The watch of the pasta of the last run of a container ends before the
    /// next run makes its namespace (the cleanup command of the monitor,
    /// another process, tore that run down): a watch that saw its pasta go
    /// late could start pasta on the namespace of the next run.
    #[tokio::test]
    async fn the_watch_of_the_last_run_ends_before_the_next_run() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        let nets = ContainerNetworks::new(
            db,
            EngineOptions {
                state_dir: dir.path().to_path_buf(),
                db_path: dir.path().join("db.sqlite"),
                bridge: BridgeConfig::default(),
                table: "t".into(),
                dns_exe: "velarx".into(),
                cni: velarx_config::CniConfig::default(),
                providers: Vec::new(),
            },
        )
        .unwrap();
        let fake = super::super::pasta::tests::FakePasta::new();
        fake.start();
        nets.pasta.watch(
            "c",
            fake.argv.clone(),
            &fake.netns,
            &fake.pid_file,
            &fake.log_file,
        );
        nets.unwatch("c").await.unwrap();
        assert!(!nets.pasta.is_watched("c"), "the watch outlived the run");
        fake.kill();
        assert!(!fake.started_now(), "pasta was started on the next run");
    }

    /// A rootless engine without pasta in its `$PATH`: nothing in the
    /// default is a fallback.  The default network, `pasta` and a pod's
    /// `pasta` fail with the typed error; `none` and `host` plan as asked.
    #[tokio::test]
    async fn rootless_without_pasta_fails_and_does_not_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        super::super::pasta::tests::search_in(&[empty.path()]);
        let db = Database::open_in_memory().await.unwrap();
        let mut nets = ContainerNetworks::new(
            db,
            EngineOptions {
                state_dir: dir.path().to_path_buf(),
                db_path: dir.path().join("db.sqlite"),
                bridge: BridgeConfig::default(),
                table: "t".into(),
                dns_exe: "velarx".into(),
                cni: velarx_config::CniConfig::default(),
                providers: Vec::new(),
            },
        )
        .unwrap();
        nets.rootless = true;
        for (mode, networks) in [
            ("", &[][..]),
            ("default", &[]),
            ("pasta", &[]),
            ("pasta:--ipv4-only", &[]),
            ("", &["pasta"]),
        ] {
            let e = nets.plan(&req(mode, networks)).await.unwrap_err();
            assert!(
                matches!(e, NetworkError::NoPasta { .. }),
                "{mode:?} {networks:?}: {e}"
            );
        }
        for mode in ["none", "host"] {
            let planned = nets.plan(&req(mode, &[])).await.unwrap();
            assert_eq!(
                planned.spec.mode,
                if mode == "none" {
                    Mode::None
                } else {
                    Mode::Host
                }
            );
        }
        // (with pasta, the default is pasta)
        super::super::pasta::tests::fake_version(empty.path(), "pasta 2026_10_02.cba3570");
        let planned = nets.plan(&req("", &[])).await.unwrap();
        assert_eq!(planned.spec.mode, Mode::Pasta);
    }

    fn req(mode: &str, nets: &[&str]) -> NetRequest {
        NetRequest {
            network_mode: NetworkMode::parse(mode),
            networks: nets.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// Nothing asked for and `default` are the default network (pasta
    /// rootless); `bridge` is asked for.
    #[test]
    fn only_the_default_network_is_implicit() {
        for (mode, implicit) in [
            ("", true),
            ("default", true),
            ("private", true),
            ("bridge", false),
        ] {
            let (m, _, _, i) = parse_modes(&req(mode, &[])).unwrap();
            assert_eq!(m, Mode::Bridge, "{mode:?}");
            assert_eq!(i, implicit, "{mode:?}");
        }
    }

    #[test]
    fn pod_cidrs() {
        for ok in ["10.244.1.0/24", "fd00:1::/64", "0.0.0.0/0", "::/0"] {
            assert!(is_cidr(ok), "{ok}");
        }
        for bad in [
            "10.0.0.0",
            "10.0.0.0/33",
            "fd00::/129",
            "x/8",
            "10.0.0.0/",
            "/8",
            "",
        ] {
            assert!(!is_cidr(bad), "{bad}");
        }
    }

    #[test]
    fn the_default_network_is_podmans_on_a_bridge_of_its_own() {
        let cfg: BridgeConfig = toml::from_str("").unwrap();
        let b = NetworkDef::builtin(&cfg).unwrap();
        assert_eq!(b.name, "podman");
        // podman's: sha256("podman").
        assert_eq!(
            b.id,
            "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9"
        );
        assert_eq!(b.bridge, "velarx0");
        assert_ne!(b.bridge, "podman0");
    }

    #[test]
    fn modes() {
        let m = |mode: &str, nets: &[&str]| {
            parse_modes(&req(mode, nets))
                .map(|r| (r.0, r.1.into_iter().map(|b| b.0).collect::<Vec<_>>(), r.3))
        };
        assert_eq!(
            m("", &[]).unwrap(),
            (Mode::Bridge, vec![String::new()], true)
        );
        assert_eq!(
            m("bridge", &[]).unwrap(),
            (Mode::Bridge, vec![String::new()], false)
        );
        assert_eq!(
            m("", &["a", "b"]).unwrap(),
            (Mode::Bridge, vec!["a".into(), "b".into()], false)
        );
        assert_eq!(
            m("a,b", &[]).unwrap().1,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            m("", &["a,b", "c"]).unwrap().1,
            vec!["a".to_string(), "b".into(), "c".into()]
        );
        assert_eq!(m("host", &[]).unwrap().0, Mode::Host);
        assert_eq!(m("none", &[]).unwrap().0, Mode::None);
        for slirp in ["slirp4netns", "slirp4netns:allow_host_loopback=true"] {
            let err = m(slirp, &[]).unwrap_err().to_string();
            assert!(err.contains("slirp4netns is not supported"), "{err}");
        }
        assert_eq!(m("", &["pasta", "provider:x"]).unwrap().0, Mode::Pasta);
        assert_eq!(m("container:abc", &[]).unwrap().0, Mode::Other);
        assert_eq!(
            m("cni:", &[]).unwrap(),
            (Mode::Cni, vec![String::new()], false)
        );
        assert_eq!(m("", &["cni:k8s"]).unwrap().1, vec!["k8s".to_string()]);
        assert!(m("cni:a b", &[]).is_err());
        assert!(m("", &["cni:a", "host"]).is_err());
        assert_eq!(m("provider:x", &[]).unwrap().0, Mode::Other);
        assert!(m("host", &["host", "a"]).is_err());
        assert!(m("a;b", &[]).is_err());
        // (`pod` names a network, `bridge:` takes options; the words of the
        // default network, trimmed, in a list too)
        assert_eq!(m("pod", &[]).unwrap().1, vec!["pod".to_string()]);
        assert!(m("bridge:x", &[]).is_err());
        assert_eq!(
            m("", &["default", " private"]).unwrap(),
            (Mode::Bridge, vec![String::new(), String::new()], true)
        );
        assert_eq!(m(" host", &[]).unwrap().0, Mode::Host);
        let (mode, _, opts, _) = parse_modes(&req("pasta:--ipv4-only,-a,10.0.2.0", &[])).unwrap();
        assert_eq!(mode, Mode::Pasta);
        assert_eq!(opts, vec!["--ipv4-only", "-a", "10.0.2.0"]);
    }

    #[test]
    fn the_options_of_a_network() {
        let (_, nets, _, _) = parse_modes(&req(
            "",
            &[
                "n1:ip=10.90.1.60,mac=02:42:ac:11:00:98,interface_name=foo0",
                "n2:ip6=fd00::5,alias=a,alias=b",
                "n3",
                "bridge:alias=c",
            ],
        ))
        .unwrap();
        let names: Vec<&str> = nets.iter().map(|n| n.0.as_str()).collect();
        assert_eq!(names, ["n1", "n2", "n3", ""]);
        assert_eq!(
            nets[0].1,
            NetOptions {
                ip: Some(Ipv4Addr::new(10, 90, 1, 60)),
                mac: Some([2, 0x42, 0xac, 0x11, 0, 0x98]),
                ifname: Some("foo0".into()),
                ..Default::default()
            }
        );
        assert_eq!(nets[1].1.ip6, Some("fd00::5".parse().unwrap()));
        assert_eq!(nets[1].1.aliases, ["a", "b"]);
        assert_eq!(nets[2].1, NetOptions::default());
        assert_eq!(nets[3].1.aliases, ["c"]);
        for bad in [
            "n:ip=nope",
            "n:ip6=10.0.0.1",
            "n:mac=zz",
            "n:interface_name=a/b",
            "n:interface_name=0123456789abcdef",
            "n:ip=10.0.0.1,ip=10.0.0.2",
            "n:colour=red",
            "n:ip",
            "n:alias=",
            "n:interface_name=",
            ":ip=10.0.0.1",
        ] {
            assert!(parse_modes(&req("", &[bad])).is_err(), "{bad}");
        }
        // (pasta has no options of a network)
        assert!(parse_modes(&req("", &["pasta", "n:ip=10.0.0.1"])).is_err());
    }

    #[test]
    fn the_interface_names_of_the_networks() {
        let names = |a: &[&str]| {
            let o: Vec<NetOptions> = a
                .iter()
                .map(|n| match *n {
                    "" => NetOptions::default(),
                    n => NetOptions::parse("n", &format!("interface_name={n}")).unwrap(),
                })
                .collect();
            ifnames(&o)
        };
        assert_eq!(names(&["", ""]).unwrap(), ["eth0", "eth1"]);
        assert_eq!(names(&["foo0", ""]).unwrap(), ["foo0", "eth0"]);
        // (a network without one gets the first `ethN` no other has)
        assert_eq!(names(&["", "eth0", ""]).unwrap(), ["eth1", "eth0", "eth2"]);
        assert!(names(&["foo0", "foo0"]).is_err());
        assert_eq!(free_ifname(["eth0", "foo0", "eth2"].into_iter()), "eth1");
    }

    #[test]
    fn a_cni_result_is_the_interface_of_the_container() {
        let r = serde_json::json!({
            "interfaces": [{"name": "cni0"}, {"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "sandbox": "/run/netns/x"}],
            "ips": [
                {"address": "10.1.2.3/24", "gateway": "10.1.2.1", "interface": 1},
                {"address": "fd00::3/64", "gateway": "fd00::1", "interface": 1}
            ]
        });
        let i = cni_interface("k8s", &r).unwrap();
        assert_eq!(
            (i.network.as_str(), i.ifname.as_str(), i.mac.as_str()),
            ("k8s", "eth0", "aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            (i.ip, i.prefix, i.gateway),
            (
                Some("10.1.2.3".parse().unwrap()),
                24,
                "10.1.2.1".parse().unwrap()
            )
        );
        assert_eq!(
            (i.ip6, i.prefix6, i.gateway6),
            (
                Some("fd00::3".parse().unwrap()),
                64,
                Some("fd00::1".parse().unwrap())
            )
        );
        assert!(cni_interface("k8s", &serde_json::json!({})).is_none());
    }

    #[test]
    fn records() {
        let rec = |opts: &str| NetworkRecord {
            id: "0123abcd-456".into(),
            name: "n".into(),
            driver: "bridge".into(),
            subnet: Some("10.90.0.0/24".into()),
            gateway: None,
            options: Some(opts.into()),
            created_at: String::new(),
            subnet6: None,
            gateway6: None,
        };
        let n = NetworkDef::from_record(&rec("{}")).unwrap().unwrap();
        assert_eq!(n.bridge, "br-0123abcd");
        assert_eq!(n.gateway, Ipv4Addr::new(10, 90, 0, 1));
        assert!(n.dns && !n.internal && n.mtu == 0);
        assert!(n.routes.is_empty());
        let n = NetworkDef::from_record(&rec(
            r#"{"routes":"10.0.0.0/24,10.90.0.5;10.1.0.0/16,10.90.0.6,100"}"#,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            n.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.0/24,10.90.0.5", "10.1.0.0/16,10.90.0.6,100"]
        );
        let n = NetworkDef::from_record(&rec(
            r#"{"internal":"true","disable_dns":"true","mtu":"1400","dns":"10.0.0.53","ip_range":"10.90.0.100-10.90.0.110","interface_name":"shx0"}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(n.internal && !n.dns);
        assert_eq!((n.mtu, n.bridge.as_str()), (1400, "shx0"));
        assert_eq!(n.dns_servers, vec!["10.0.0.53".parse::<IpAddr>().unwrap()]);
        let c = choice(&n, None, None);
        assert_eq!(
            (c.first, c.last),
            (Ipv4Addr::new(10, 90, 0, 100), Ipv4Addr::new(10, 90, 0, 110))
        );
        assert!(NetworkDef::from_record(&rec(r#"{"mtu":"9x"}"#)).is_err());
        let mut other = rec("{}");
        other.driver = "overlay".into();
        assert!(NetworkDef::from_record(&other).unwrap().is_none());
    }
}
