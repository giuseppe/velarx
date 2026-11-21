// SPDX-License-Identifier: Apache-2.0
//! The settings of `velarx-p2p`: the table `settings` of its source in the
//! configuration of the engine (`[[sources.external]]`, the one named by
//! `--source`), with `settings.serving` and `settings.overlay` in it and
//! every key in `config.toml.example`.  The engine does not read them; the
//! paths of the engine (the services directory the sockets are in) come from
//! the rest of the configuration.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use velarx_config::{Config, PullConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Control socket; the sockets of the fetcher and of the overlay network
    /// are next to it
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// Where the node listens (multiaddr); loopback by default, so that
    /// starting the service opens nothing to the network until the file
    /// names an address
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Where the node may dial (the addresses of the DHT, of the peers it
    /// is told of and of mDNS, not the bootstrap peers named above).  Refused
    /// unless allowed: loopback, link-local, multicast, unspecified and
    /// reserved addresses and the addresses of the interfaces of the node
    /// itself; `dial_allow` (networks, `10.0.0.0/8`) lets addresses through
    /// those refusals
    #[serde(default)]
    pub dial_allow: Vec<ipnet::IpNet>,
    /// The connections the node keeps: with fewer the bootstrap peers are
    /// dialed again, after 1 s, then twice as long each time up to
    /// `bootstrap_retry_max_secs` (0: they are dialed once, at the start)
    #[serde(default = "default_min_peers")]
    pub min_peers: usize,
    /// The longest wait between two attempts to reach the bootstrap peers
    #[serde(default = "default_bootstrap_retry_max_secs")]
    pub bootstrap_retry_max_secs: u64,
    /// Connections accepted from the peers, and made to them
    #[serde(default = "default_max_incoming")]
    pub max_incoming: u32,
    #[serde(default = "default_max_outgoing")]
    pub max_outgoing: u32,
    /// Seconds a connection that nothing uses is kept (a day by default: a
    /// connection is what makes a peer a member of the node's tables)
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Find nodes of the same swarm on the local network with mDNS
    #[serde(default)]
    pub mdns: bool,
    /// The private network (swarm) key file
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
    /// The certificate authority of the swarm (`velarx-p2p ca init`): the
    /// PEM file with the certificate of one or more authorities, and the
    /// certificate of this node (`ca sign`).  Both set, the peers are
    /// admitted by their certificates, in the QUIC handshake and when a
    /// libp2p connection is made, and `private_key_path` becomes optional
    /// (an outer layer of the TCP transport only); both files are read again
    /// when they change.  Their directories are readable by the service
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,
    /// The revocation lists the authority signed (`ca revoke`), read again
    /// when the file changes and passed along on new connections
    #[serde(default)]
    pub revocation_path: Option<PathBuf>,
    /// No peer is admitted when the revocation file was not read (validly)
    /// for this long (0: not checked)
    #[serde(default)]
    pub revocation_max_age_secs: u64,
    /// Only the peers with these names (of their certificates) or peer ids
    /// are admitted (the node itself need not be one); both empty: every
    /// certificate of the authority
    #[serde(default)]
    pub allow_names: Vec<String>,
    #[serde(default)]
    pub allow_peers: Vec<String>,
    /// Seconds between two readings of the authority's files and two
    /// judgements of the peers admitted (a revoked or expired peer is cut
    /// off at the next; 1 to 3600)
    #[serde(default = "default_ca_sweep_secs")]
    pub ca_sweep_secs: u64,
    /// The file of the identity of the node (its peer id), made at the first
    /// start; by default `p2p/identity.key` in the root directory of the
    /// engine
    #[serde(default)]
    pub identity_path: Option<PathBuf>,
    /// The UDP port of the QUIC endpoint, which carries all the data (0: any,
    /// for tests); by default the port of the first TCP listen address
    #[serde(default)]
    pub quic_port: Option<u16>,
    /// The QUIC streams a request for chunks to one peer is spread over
    /// (1 to 8)
    #[serde(default = "default_quic_streams")]
    pub quic_streams: usize,
    /// Ask a second peer for chunks when the first is slow to answer
    #[serde(default = "default_true")]
    pub hedge: bool,
    /// Milliseconds to wait for a peer before the second is asked; 0: three
    /// times the time that peer usually takes (50 ms to 2 s)
    #[serde(default)]
    pub hedge_ms: u64,
    /// The peers a big group of chunks is spread over (0 or 1: one at a time)
    #[serde(default = "default_stripe_peers")]
    pub stripe_peers: usize,
    /// The largest file the service writes (MiB)
    #[serde(default = "default_max_incoming_mib")]
    pub max_incoming_mib: u64,
    /// Tell the peers the images this node has (they can list them) and
    /// publish its layers in the DHT; off, a peer can only test a layer in
    /// the filter or ask for one digest
    #[serde(default)]
    pub announce_images: bool,
    /// Tell the peers a filter of the layers this node holds (a member can
    /// test a layer it knows in it, not list them); off, the peers ask the
    /// node one digest at a time
    #[serde(default = "default_true")]
    pub advertise_layers: bool,
    /// The rate at which the filter says "maybe" to a layer the node does
    /// not hold (0.0001 to 0.1)
    #[serde(default = "default_filter_fpr")]
    pub filter_fpr: f64,
    /// The largest filter the node sends, in KiB (1 to 4096)
    #[serde(default = "default_filter_max_kib")]
    pub filter_max_kib: usize,
    /// The least time between two updates of the filter sent to the peers,
    /// in seconds: the layers that complete meanwhile go in one (1 to 3600)
    #[serde(default = "default_filter_interval_secs")]
    pub filter_interval_secs: u64,
    /// The connected peers asked at once whether they have a chunk when no
    /// peer is known to (0: none)
    #[serde(default = "default_query_peers")]
    pub query_peers: usize,
    /// What the node serves to the peers, at most
    #[serde(default)]
    pub serving: crate::Serving,
    #[serde(default)]
    pub overlay: Overlay,
}

/// The overlay network of the containers (`--network provider:NAME`, the
/// name of a `[[network.providers]]` whose socket is `p2p-network.sock`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    /// Where the overlay node listens (multiaddr); it is a member of the
    /// swarm of its own (`velarx-p2p overlay`): the same swarm key or
    /// authority, its own identity, port and DHT
    #[serde(default = "default_overlay_listen_addresses")]
    pub listen_addresses: Vec<String>,
    /// The overlay ports of other nodes
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// The file of the identity of the overlay node; by default
    /// `p2p/overlay-identity.key` in the root directory of the engine
    #[serde(default)]
    pub identity_path: Option<PathBuf>,
    /// With an authority (`ca_path`), the certificate of the overlay node
    /// (`ca request --identity` of its identity file, then `ca sign`)
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,
    /// The range each node takes a /24 of (a /8 to a /16)
    #[serde(default = "default_cidr")]
    pub cidr: String,
    /// The number of the /24 of the node among the 16 its peer id gives
    #[serde(default)]
    pub subnet_attempt: u8,
    /// The name servers the containers' names that are not containers go
    /// to (an address, with a port or without: 53); none: those of the
    /// host's `/etc/resolv.conf`
    #[serde(default)]
    pub dns_upstreams: Vec<String>,
    /// The routing table where the node's address (the containers' name
    /// server) is local; change it when the host uses 53053
    #[serde(default = "default_dns_table")]
    pub dns_table: u32,
    /// The priority of the rules that send the DNS of the containers to
    /// that table (1 to 32765); change it when the host uses 5353
    #[serde(default = "default_dns_rule_priority")]
    pub dns_rule_priority: u32,
}

fn default_dns_table() -> u32 {
    crate::overlay_helper::DnsRouting::DEFAULT.table
}

fn default_dns_rule_priority() -> u32 {
    crate::overlay_helper::DnsRouting::DEFAULT.rule_priority
}

fn default_listen_addresses() -> Vec<String> {
    vec!["/ip4/127.0.0.1/tcp/4001".to_string()]
}

fn default_overlay_listen_addresses() -> Vec<String> {
    vec!["/ip4/127.0.0.1/tcp/4002".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_quic_streams() -> usize {
    4
}

fn default_stripe_peers() -> usize {
    3
}

fn default_query_peers() -> usize {
    8
}

fn default_filter_fpr() -> f64 {
    crate::filter::Config::default().fpr
}

fn default_filter_max_kib() -> usize {
    crate::filter::Config::default().max_bytes >> 10
}

fn default_filter_interval_secs() -> u64 {
    crate::filter::Config::default().interval.as_secs()
}

fn default_ca_sweep_secs() -> u64 {
    10
}

fn default_min_peers() -> usize {
    4
}

fn default_bootstrap_retry_max_secs() -> u64 {
    60
}

fn default_max_incoming() -> u32 {
    100
}

fn default_max_outgoing() -> u32 {
    50
}

fn default_idle_timeout_secs() -> u64 {
    24 * 3600
}

fn default_max_incoming_mib() -> u64 {
    256
}

fn default_cidr() -> String {
    "10.192.0.0/10".to_string()
}

impl Default for Overlay {
    fn default() -> Self {
        Self {
            listen_addresses: default_overlay_listen_addresses(),
            bootstrap_peers: Vec::new(),
            identity_path: None,
            certificate_path: None,
            cidr: default_cidr(),
            subnet_attempt: 0,
            dns_upstreams: Vec::new(),
            dns_table: default_dns_table(),
            dns_rule_priority: default_dns_rule_priority(),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            socket: None,
            listen_addresses: default_listen_addresses(),
            bootstrap_peers: Vec::new(),
            dial_allow: Vec::new(),
            min_peers: default_min_peers(),
            bootstrap_retry_max_secs: default_bootstrap_retry_max_secs(),
            max_incoming: default_max_incoming(),
            max_outgoing: default_max_outgoing(),
            idle_timeout_secs: default_idle_timeout_secs(),
            mdns: false,
            private_key_path: None,
            ca_path: None,
            certificate_path: None,
            revocation_path: None,
            revocation_max_age_secs: 0,
            allow_names: Vec::new(),
            allow_peers: Vec::new(),
            ca_sweep_secs: default_ca_sweep_secs(),
            identity_path: None,
            quic_port: None,
            quic_streams: default_quic_streams(),
            hedge: true,
            hedge_ms: 0,
            stripe_peers: default_stripe_peers(),
            max_incoming_mib: default_max_incoming_mib(),
            announce_images: false,
            advertise_layers: true,
            filter_fpr: default_filter_fpr(),
            filter_max_kib: default_filter_max_kib(),
            filter_interval_secs: default_filter_interval_secs(),
            query_peers: default_query_peers(),
            serving: crate::Serving::default(),
            overlay: Overlay::default(),
        }
    }
}

impl Settings {
    /// The settings of the source `name` of the configuration (its
    /// `settings` in `[[sources.external]]`; the defaults when there is no
    /// such source); a relative key path is relative to the directory of the
    /// configuration file.
    pub fn load(config: &Config, name: &str, config_dir: &Path) -> anyhow::Result<Self> {
        let table = config
            .sources
            .external
            .iter()
            .find(|source| source.name == name)
            .map(|source| source.settings.clone())
            .unwrap_or_default();
        Self::from_table(table, config_dir)
            .map_err(|e| anyhow::anyhow!("the settings of the source `{name}`: {e}"))
    }

    fn from_table(table: toml::Table, config_dir: &Path) -> anyhow::Result<Self> {
        let mut settings: Self = toml::Value::Table(table).try_into()?;
        for file in [
            &mut settings.private_key_path,
            &mut settings.identity_path,
            &mut settings.ca_path,
            &mut settings.certificate_path,
            &mut settings.revocation_path,
            &mut settings.overlay.identity_path,
            &mut settings.overlay.certificate_path,
        ] {
            if let Some(name) = file.as_ref().filter(|name| name.is_relative()) {
                *file = Some(config_dir.join(name));
            }
        }
        settings.validate()?;
        Ok(settings)
    }

    /// Refuse settings that do not mean what they say.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1..=8).contains(&self.quic_streams) {
            anyhow::bail!("quic_streams must be 1 to 8");
        }
        if self.query_peers > 64 {
            anyhow::bail!("query_peers must be 0 to 64");
        }
        if self.max_incoming == 0 || self.max_outgoing == 0 {
            anyhow::bail!("max_incoming and max_outgoing must not be 0");
        }
        if self.min_peers as u64 > u64::from(self.max_outgoing) {
            anyhow::bail!("min_peers must not be more than max_outgoing");
        }
        if self.min_peers > 0 && self.bootstrap_retry_max_secs == 0 {
            anyhow::bail!("bootstrap_retry_max_secs must not be 0 (min_peers = 0 dials once)");
        }
        if self.idle_timeout_secs == 0 {
            anyhow::bail!("idle_timeout_secs must not be 0");
        }
        if !(0.0001..=0.1).contains(&self.filter_fpr) {
            anyhow::bail!("filter_fpr must be 0.0001 to 0.1");
        }
        if !(1..=4096).contains(&self.filter_max_kib) {
            anyhow::bail!("filter_max_kib must be 1 to 4096");
        }
        if !(1..=3600).contains(&self.filter_interval_secs) {
            anyhow::bail!("filter_interval_secs must be 1 to 3600");
        }
        if !(1..=3600).contains(&self.ca_sweep_secs) {
            anyhow::bail!("ca_sweep_secs must be 1 to 3600");
        }
        self.serving.validate().map_err(|e| anyhow::anyhow!(e))?;
        if self.max_incoming_mib == 0 {
            anyhow::bail!("max_incoming_mib must not be 0");
        }
        for (key, addresses) in [
            ("listen_addresses", &self.listen_addresses),
            ("bootstrap_peers", &self.bootstrap_peers),
            (
                "settings.overlay.listen_addresses",
                &self.overlay.listen_addresses,
            ),
            (
                "settings.overlay.bootstrap_peers",
                &self.overlay.bootstrap_peers,
            ),
        ] {
            for a in addresses {
                a.parse::<libp2p::Multiaddr>()
                    .map_err(|e| anyhow::anyhow!("{key}: `{a}` is not a multiaddress: {e}"))?;
            }
        }
        if self.listen_addresses.is_empty() || self.overlay.listen_addresses.is_empty() {
            anyhow::bail!("listen_addresses must name at least one address");
        }
        if self.ca_path.is_some() != self.certificate_path.is_some() {
            anyhow::bail!("ca_path and certificate_path are set together: the authorities and the certificate of this node");
        }
        if self.ca_path.is_none()
            && (self.revocation_path.is_some()
                || self.revocation_max_age_secs > 0
                || !self.allow_names.is_empty()
                || !self.allow_peers.is_empty())
        {
            anyhow::bail!(
                "revocation_path, revocation_max_age_secs, allow_names and allow_peers need ca_path"
            );
        }
        crate::overlay_helper::DnsRouting::check(
            self.overlay.dns_table,
            self.overlay.dns_rule_priority,
        )
        .map_err(|e| anyhow::anyhow!("settings.overlay.dns_table, dns_rule_priority: {e}"))?;
        Ok(())
    }

    /// The authority of the settings, for the node with the key `identity`;
    /// none without `ca_path`.
    pub fn authority(
        &self,
        identity: &libp2p::identity::Keypair,
    ) -> anyhow::Result<Option<std::sync::Arc<crate::authority::Authority>>> {
        let (Some(ca_path), Some(certificate_path)) = (&self.ca_path, &self.certificate_path)
        else {
            return Ok(None);
        };
        let allow_peers = self
            .allow_peers
            .iter()
            .map(|p| p.parse())
            .collect::<Result<_, _>>()?;
        crate::authority::Authority::load(
            crate::authority::Config {
                ca_path: ca_path.clone(),
                certificate_path: certificate_path.clone(),
                revocation_path: self.revocation_path.clone(),
                revocation_max_age: std::time::Duration::from_secs(self.revocation_max_age_secs),
                allow_names: self.allow_names.clone(),
                allow_peers,
                sweep: std::time::Duration::from_secs(self.ca_sweep_secs),
            },
            identity,
        )
        .map(Some)
        .map_err(|e| anyhow::anyhow!("the certificate authority: {e}"))
    }

    /// The settings of the overlay node: those of the service with its own
    /// addresses, identity and certificate, and no mDNS (it would find the
    /// content nodes).
    pub fn of_overlay(&self, config: &Config) -> anyhow::Result<Self> {
        let overlay = &self.overlay;
        if self.ca_path.is_some() && overlay.certificate_path.is_none() {
            anyhow::bail!(
                "settings.overlay.certificate_path: with ca_path the overlay node needs a certificate \
                 of its own identity"
            );
        }
        let settings = Self {
            listen_addresses: overlay.listen_addresses.clone(),
            bootstrap_peers: overlay.bootstrap_peers.clone(),
            identity_path: Some(overlay.identity_path.clone().unwrap_or_else(|| {
                config
                    .server
                    .root_dir
                    .join("p2p")
                    .join("overlay-identity.key")
            })),
            certificate_path: overlay.certificate_path.clone(),
            mdns: false,
            ..self.clone()
        };
        settings.validate()?;
        Ok(settings)
    }

    /// The file of the identity of the node: in the state that outlives
    /// the run directory, not in it.
    pub fn identity_file(&self, config: &Config) -> PathBuf {
        self.identity_path
            .clone()
            .unwrap_or_else(|| config.server.root_dir.join("p2p").join("identity.key"))
    }

    /// The control socket (`velarx-p2p status` asks it).
    pub fn control_socket(&self, config: &Config) -> PathBuf {
        self.socket
            .clone()
            .unwrap_or_else(|| config.services_dir().join("p2p.sock"))
    }

    /// The socket on which the service is a fetcher (`org.velarx.Fetcher`):
    /// the sources of the engine name it.
    pub fn fetcher_socket(&self, config: &Config) -> PathBuf {
        self.sibling_socket(config, "p2p-fetcher.sock")
    }

    /// The socket of the overlay network (`org.velarx.Network`): a network
    /// provider of the engine names it.
    pub fn network_socket(&self, config: &Config) -> PathBuf {
        self.sibling_socket(config, "p2p-network.sock")
    }

    fn sibling_socket(&self, config: &Config, name: &str) -> PathBuf {
        match &self.socket {
            Some(socket) => socket.with_file_name(name),
            None => config.services_dir().join(name),
        }
    }

    /// The largest file the service writes (`max_incoming_mib`), never more
    /// than a layer.
    pub fn max_file_bytes(&self, pull: &PullConfig) -> u64 {
        self.max_incoming_mib
            .saturating_mul(1 << 20)
            .min(pull.max_file_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header of the overlay's settings.
    const OVERLAY: &str = "[sources.external.settings.overlay]\n";

    /// The settings of the source `p2p` with this text in them.
    fn parse(text: &str) -> anyhow::Result<Settings> {
        let config: Config = toml::from_str(&format!(
            "[[sources.external]]\nname = \"p2p\"\nsocket = \"/s\"\n\
             [sources.external.settings]\n{text}"
        ))?;
        Settings::load(&config, "p2p", Path::new("/etc/velarx"))
    }

    /// The settings of the source `p2p` of the example configuration.
    fn example() -> Settings {
        let config: Config = toml::from_str(include_str!("../../../config.toml.example")).unwrap();
        Settings::load(&config, "p2p", Path::new("/etc/velarx")).unwrap()
    }

    /// The settings are those of the source named, as they are written, and
    /// the defaults when no source has the name.
    #[test]
    fn the_settings_are_those_of_the_source_named() {
        let config: Config = toml::from_str(
            "[[sources.external]]\nname = \"other\"\nsocket = \"/o\"\n\
             [sources.external.settings]\nquic_streams = 9\n\
             [[sources.external]]\nname = \"peers\"\nsocket = \"/p\"\n\
             [sources.external.settings]\nquic_streams = 2\nmdns = true\n\
             [sources.external.settings.serving]\nquic_slots = 7\n",
        )
        .unwrap();
        let s = Settings::load(&config, "peers", Path::new("/etc/velarx")).unwrap();
        assert_eq!((s.quic_streams, s.mdns, s.serving.quic_slots), (2, true, 7));
        let e = Settings::load(&config, "other", Path::new("/etc/velarx")).unwrap_err();
        assert!(e.to_string().contains("`other`"), "{e}");
        let s = Settings::load(&config, "p2p", Path::new("/etc/velarx")).unwrap();
        assert_eq!(s.quic_streams, 4);
    }

    /// A table or a priority of the DNS routing that is the kernel's is
    /// refused when the settings are read, not when the overlay starts.
    #[test]
    fn the_kernels_routing_tables_are_refused() {
        assert!(parse(&format!("{OVERLAY}dns_table = 254\n")).is_err());
        assert!(parse(&format!("{OVERLAY}dns_rule_priority = 32766\n")).is_err());
        let s = parse(&format!(
            "{OVERLAY}dns_table = 7777\ndns_rule_priority = 700\n"
        ))
        .unwrap();
        assert_eq!(
            (s.overlay.dns_table, s.overlay.dns_rule_priority),
            (7777, 700)
        );
    }

    /// An address that is not a multiaddress is refused when the settings
    /// are read: skipped, the node would listen on none and its QUIC
    /// endpoint would bind every interface.
    #[test]
    fn a_listen_or_bootstrap_address_that_is_no_multiaddr_is_refused() {
        assert!(parse("listen_addresses = [\"/ip4/127.0.0.1/tcpx/1\"]\n").is_err());
        assert!(parse("listen_addresses = [\"127.0.0.1:4001\"]\n").is_err());
        assert!(parse("bootstrap_peers = [\"/ip4/10.0.0.1/tcp\"]\n").is_err());
        assert!(parse("listen_addresses = []\n").is_err());
        assert!(parse(
            "listen_addresses = [\"/ip4/127.0.0.1/tcp/4001\"]\nbootstrap_peers = [\"/ip4/10.0.0.1/tcp/4001\"]\n"
        )
        .is_ok());
    }

    #[test]
    fn no_settings_are_the_defaults() {
        let s = Settings::load(&Config::default(), "p2p", Path::new("/etc/velarx")).unwrap();
        assert_eq!(s.quic_streams, 4);
        assert!(!s.announce_images, "no list of images is told by default");
        assert!(
            s.advertise_layers,
            "the filter of the layers is told by default"
        );
        assert_eq!(s.filter_fpr, 0.01);
        assert_eq!(s.query_peers, 8);
    }

    #[test]
    fn quic_streams_and_the_incoming_file_are_checked() {
        assert!(parse("quic_streams = 0\n").is_err());
        assert!(parse("quic_streams = 9\n").is_err());
        assert!(parse("max_incoming_mib = 0\n").is_err());
        assert_eq!(parse("quic_streams = 2\n").unwrap().quic_streams, 2);
        assert!(parse("query_peers = 65\n").is_err());
        assert!(parse("announce_images = true\n").unwrap().announce_images);
        assert!(
            !parse("advertise_layers = false\n")
                .unwrap()
                .advertise_layers
        );
        for bad in [
            "filter_fpr = 0.5\n",
            "filter_fpr = 0.0\n",
            "filter_max_kib = 0\n",
            "filter_max_kib = 5000\n",
            "filter_interval_secs = 0\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_key_that_is_not_a_setting_is_an_error() {
        assert!(parse("quicc = true\n").is_err());
        assert!(parse(&format!("{OVERLAY}x = 1\n")).is_err());
    }

    #[test]
    fn the_identity_is_in_the_state_of_the_engine_unless_named() {
        let config = Config::default();
        let s = Settings::default();
        assert_eq!(
            s.identity_file(&config),
            config.server.root_dir.join("p2p/identity.key")
        );
        let s = parse("identity_path = \"me.key\"\n").unwrap();
        assert_eq!(s.identity_file(&config), Path::new("/etc/velarx/me.key"));
    }

    #[test]
    fn the_key_is_relative_to_the_configuration_file() {
        let s = parse("private_key_path = \"swarm.key\"\n").unwrap();
        assert_eq!(s.private_key_path, Some("/etc/velarx/swarm.key".into()));
    }

    #[test]
    fn the_sockets_are_next_to_each_other() {
        let mut config = Config::default();
        config.server.socket = "/run/x/velarx.sock".into();
        let s = Settings::default();
        assert_eq!(
            s.control_socket(&config),
            Path::new("/run/x/services/p2p.sock")
        );
        assert_eq!(
            s.fetcher_socket(&config),
            Path::new("/run/x/services/p2p-fetcher.sock")
        );
        let s = parse("socket = \"/other/p.sock\"\n").unwrap();
        assert_eq!(
            s.network_socket(&config),
            Path::new("/other/p2p-network.sock")
        );
    }

    /// Starting the service opens nothing to the network until the file
    /// says so: loopback, no mDNS (an empty table and the example agree).
    #[test]
    fn the_defaults_open_nothing_to_the_network() {
        let s = parse("").unwrap();
        assert_eq!(s.listen_addresses, ["/ip4/127.0.0.1/tcp/4001"]);
        assert!(!s.mdns);
        let e = example();
        assert_eq!(e.listen_addresses, s.listen_addresses);
        assert!(!e.mdns);
    }

    /// The overlay node is a member of the swarm with its own address,
    /// identity and certificate, and no mDNS.
    #[test]
    fn the_overlay_node_has_its_own_address_identity_and_certificate() {
        let config = Config::default();
        let s = parse(&format!(
            "mdns = true\nca_path = \"/ca\"\ncertificate_path = \"/node.crt\"\n\
             {OVERLAY}certificate_path = \"/overlay.crt\"\n\
             listen_addresses = [\"/ip4/192.0.2.1/tcp/4002\"]\n",
        ))
        .unwrap();
        let o = s.of_overlay(&config).unwrap();
        assert_eq!(o.listen_addresses, ["/ip4/192.0.2.1/tcp/4002"]);
        assert_eq!(o.certificate_path, Some(PathBuf::from("/overlay.crt")));
        assert_eq!(o.ca_path, s.ca_path);
        assert!(!o.mdns);
        assert_eq!(
            o.identity_file(&config),
            config.server.root_dir.join("p2p/overlay-identity.key")
        );
        assert_ne!(o.identity_file(&config), s.identity_file(&config));
        // an authority without a certificate for the overlay node is refused
        assert!(
            parse("ca_path = \"/ca\"\ncertificate_path = \"/node.crt\"\n")
                .unwrap()
                .of_overlay(&config)
                .is_err()
        );
        // (the overlay's addresses are checked as the node's are)
        assert!(parse(&format!(
            "{OVERLAY}listen_addresses = [\"127.0.0.1:4002\"]\n"
        ))
        .is_err());
    }

    #[test]
    fn the_authority_is_set_by_its_two_files_together() {
        assert!(parse("ca_path = \"/a\"\n").is_err());
        assert!(parse("certificate_path = \"/a\"\n").is_err());
        assert!(parse("ca_path = \"/a\"\ncertificate_path = \"/b\"\n").is_ok());
        // what only an authority has needs it
        for text in [
            "revocation_path = \"/r\"\n",
            "allow_names = [\"a\"]\n",
            "allow_peers = [\"12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN\"]\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        let with = |extra: &str| {
            parse(&format!(
                "ca_path = \"/a\"\ncertificate_path = \"/b\"\n{extra}"
            ))
        };
        let s = with("revocation_path = \"r\"\n").unwrap();
        assert!(s.revocation_path.unwrap().ends_with("r"));
        assert!(with("ca_sweep_secs = 0\n").is_err());
        assert!(with("ca_sweep_secs = 3601\n").is_err());
    }

    /// Every key is in the example, which is a valid file.
    #[test]
    fn the_example_has_every_key() {
        fn names(v: &toml::Value, out: &mut Vec<String>) {
            if let toml::Value::Table(t) = v {
                for (k, v) in t {
                    out.push(k.clone());
                    names(v, out);
                }
            }
        }
        let text = include_str!("../../../config.toml.example");
        let block = text
            .lines()
            .skip_while(|l| !l.starts_with("[sources.external.settings]"));
        let v = toml::Value::try_from(Settings::default()).unwrap();
        let mut keys = Vec::new();
        names(&v, &mut keys);
        // `socket` and `private_key_path` have no default value to print
        keys.extend([
            "socket".into(),
            "private_key_path".into(),
            "ca_path".into(),
            "certificate_path".into(),
            "revocation_path".into(),
            "identity_path".into(),
            "quic_port".into(),
        ]);
        let missing: Vec<_> = keys
            .iter()
            .filter(|k| {
                !block.clone().any(|l| {
                    l.trim_start_matches([' ', '#'])
                        .split(['.', '[', ']', '='])
                        .any(|p| p.trim() == k.as_str())
                })
            })
            .collect();
        assert!(missing.is_empty(), "the example has no {missing:?}");
        assert!(example().private_key_path.is_some());
    }
}
