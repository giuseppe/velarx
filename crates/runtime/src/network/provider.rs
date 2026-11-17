// SPDX-License-Identifier: Apache-2.0
//! The varlink interface `org.velarx.Network` of a network provider, and the
//! client the engine uses: a separate process that makes the network of the
//! containers that name it (`--network provider:NAME`), configured with
//! `[[network.providers]]` (a name and a unix socket).
//!
//! The engine asks the provider for three things:
//!
//! * `Prepare`, before the runtime spec of the container is made: the
//!   interfaces of the host that the runtime moves into the container, and
//!   the DNS server for its `resolv.conf`;
//! * `Start`, once the container runs: finish its network, in the network
//!   namespace the call carries (a descriptor, never a pid: one that is
//!   reused would name another process);
//! * `Stop`, when it is not running any more: undo it.
//!
//! A client checks `GetInfo` on each connection and refuses another `proto`.
//! What the provider is, and what it connects the containers to, is its own
//! matter.  Types with serde and zlink only.

use serde::{Deserialize, Serialize};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use thiserror::Error;
use velarx_netdetach::provider::PROTO;
use velarx_proto::info::Info;
use zlink::{introspect, proxy};

/// An interface of the host to move into the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Device {
    /// The name of the interface on the host
    pub host: String,
    /// The name it has in the container
    pub container: String,
}

/// What a provider makes ready for a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Prepared {
    /// The interfaces of the host the runtime moves into the container
    pub devices: Vec<Device>,
    /// The name server of the network, for `resolv.conf`
    pub dns: Option<Ipv4Addr>,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Network")]
pub enum ProviderError {
    /// A request the provider does not take (an id it cannot use)
    InvalidArgument { reason: String },
    /// The provider knows no such container (`Start` before `Prepare`)
    NotFound { reason: String },
    /// The provider tried and failed
    Failed { reason: String },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::NotFound { reason } => write!(f, "not found: {reason}"),
            Self::Failed { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// The calls of the provider, as a client makes them.
#[proxy("org.velarx.Network")]
pub trait ProviderProxy {
    async fn get_info(&mut self) -> zlink::Result<Result<Info, ProviderError>>;
    async fn prepare(&mut self, id: &str) -> zlink::Result<Result<Prepared, ProviderError>>;
    /// The call carries one descriptor: the network namespace of the
    /// container
    async fn start(
        &mut self,
        id: &str,
        name: &str,
        default_route: bool,
        #[zlink(fds)] netns: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Ack, ProviderError>>;
    /// Idempotent: a `Stop` of a container that is not started, or was
    /// stopped, is a success (the engine's reconcile and a monitor's
    /// teardown may both call it).
    async fn stop(&mut self, id: &str) -> zlink::Result<Result<Ack, ProviderError>>;
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("the network provider does not answer on {}", .socket.display())]
    Unreachable {
        socket: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("network provider: {0}")]
    Provider(#[from] ProviderError),
    #[error("network provider: {0}")]
    Protocol(String),
}

pub type ClientResult<T> = Result<T, ClientError>;

fn protocol(e: zlink::Error) -> ClientError {
    ClientError::Protocol(e.to_string())
}

/// A client of the provider on `socket`: one connection for each call, its
/// `GetInfo` checked first.
#[derive(Debug, Clone)]
pub struct ProviderClient {
    socket: PathBuf,
}

macro_rules! call {
    ($self:ident . $method:ident ( $($arg:expr),* )) => {{
        let mut conn = velarx_content::activation::connect(&$self.socket)
            .await
            .map_err(|source| ClientError::Unreachable {
                socket: $self.socket.clone(),
                source,
            })?;
        let info = conn
            .get_info()
            .await
            .map_err(protocol)?
            .map_err(ClientError::Provider)?;
        velarx_proto::info::check("org.velarx.Network", &info, PROTO).map_err(|e| {
            ClientError::Protocol(format!("the provider on {}: {e}", $self.socket.display()))
        })?;
        conn.$method($($arg),*)
            .await
            .map_err(protocol)?
            .map_err(ClientError::Provider)
    }};
}

impl ProviderClient {
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    /// Make the network of the container ready, before its spec is made.
    pub async fn prepare(&self, id: &str) -> ClientResult<Prepared> {
        call!(self.prepare(id))
    }

    /// Finish the network of the container whose network namespace is
    /// `netns`.  `name` is what the other containers know it by;
    /// `default_route`: the network is the one that reaches the outside (no
    /// other network does).
    pub async fn start(
        &self,
        id: &str,
        name: &str,
        netns: OwnedFd,
        default_route: bool,
    ) -> ClientResult<()> {
        call!(self.start(id, name, default_route, vec![netns])).map(|_| ())
    }

    /// Undo the network of a container that is not running any more.
    pub async fn stop(&self, id: &str) -> ClientResult<()> {
        call!(self.stop(id)).map(|_| ())
    }
}

/// The providers of the configuration, by name.
#[derive(Debug, Clone, Default)]
pub struct Providers(std::collections::HashMap<String, ProviderClient>);

impl Providers {
    pub fn of_config(config: &velarx_config::Config) -> Self {
        Self(
            config
                .network
                .providers
                .iter()
                .map(|p| (p.name.clone(), ProviderClient::new(&p.socket)))
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Option<&ProviderClient> {
        self.0.get(name)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `Prepare` of each provider of NAMES (configured ones) for the
    /// container ID, in order: the interfaces to move into the container,
    /// and the name server of the first that has one.  Each provider that
    /// made the network ready is added to PREPARED: what [`Self::stop`]
    /// undoes when the container is not made after all (a provider that
    /// failed undid its own).  The error names the provider that failed.
    pub async fn prepare(
        &self,
        names: &[&str],
        id: &str,
        prepared: &mut Vec<String>,
    ) -> Result<(Vec<Device>, Option<Ipv4Addr>), (String, ClientError)> {
        let mut devices = Vec::new();
        let mut dns = None;
        for name in names {
            let Some(client) = self.get(name) else {
                continue;
            };
            let p = client
                .prepare(id)
                .await
                .map_err(|e| (name.to_string(), e))?;
            prepared.push(name.to_string());
            devices.extend(p.devices);
            dns = dns.or(p.dns);
        }
        Ok((devices, dns))
    }

    /// `Stop` of each provider of NAMES for the container ID: the network
    /// they made for it goes.  A failure is the provider's to report.
    pub async fn stop(&self, names: &[String], id: &str) {
        for name in names {
            if let Some(client) = self.get(name) {
                if let Err(e) = client.stop(id).await {
                    tracing::warn!(
                        "Network provider {name} could not undo the network of {id}: {e}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A provider that records what it is asked, of the protocol `.1`.
    #[derive(Clone)]
    struct Recorder(Arc<Mutex<Vec<String>>>, u32);

    impl Default for Recorder {
        fn default() -> Self {
            Self(Arc::default(), PROTO)
        }
    }

    #[zlink::service(
        interface = "org.velarx.Network",
        vendor = "org.velarx",
        product = "velarx",
        version = "test",
        url = "https://example.org/",
        types = [Device]
    )]
    impl Recorder {
        /// Who serves this interface and what it can do.  The first call of a
        /// connection; a client refuses a `proto` other than its own.
        async fn get_info(&self) -> Info {
            Info {
                name: "test".into(),
                version: "test".into(),
                proto: self.1,
                ..Info::default()
            }
        }

        async fn prepare(&self, id: String) -> Result<Prepared, ProviderError> {
            self.0.lock().unwrap().push(format!("prepare {id}"));
            if id == "bad" {
                return Err(ProviderError::Failed {
                    reason: "no veth".into(),
                });
            }
            Ok(Prepared {
                devices: vec![Device {
                    host: "veth0".into(),
                    container: "eth1".into(),
                }],
                dns: Some(Ipv4Addr::new(10, 200, 1, 1)),
            })
        }

        async fn start(
            &self,
            id: String,
            name: String,
            default_route: bool,
            #[zlink(fds)] netns: Vec<OwnedFd>,
        ) -> Result<Ack, ProviderError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("start {id} {name} {} {default_route}", netns.len()));
            Ok(Ack {})
        }

        async fn stop(&self, id: String) -> Result<Ack, ProviderError> {
            self.0.lock().unwrap().push(format!("stop {id}"));
            Ok(Ack {})
        }
    }

    /// Serve `recorder` on a socket in `dir` (in the `LocalSet` of the
    /// caller).
    fn serve(dir: &Path, recorder: &Recorder) -> PathBuf {
        let dir_path = dir.join("private");
        velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
        let socket = dir_path.join("net.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::task::spawn_local(velarx_content::activation::serve_varlink(
            listener,
            None,
            velarx_base::ipc::trusted_uid,
            velarx_content::activation::Limits::default(),
            "test provider",
            recorder.clone(),
        ));
        socket
    }

    /// A provider of another version of the protocol is refused before
    /// any call.
    #[tokio::test]
    async fn a_provider_of_another_protocol_is_refused() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let recorder = Recorder(Arc::default(), PROTO + 1);
                let client = ProviderClient::new(&serve(dir.path(), &recorder));
                let err = client.prepare("c1").await.unwrap_err();
                assert!(matches!(err, ClientError::Protocol(_)), "{err}");
                assert!(recorder.0.lock().unwrap().is_empty());
            })
            .await;
    }

    /// The client makes the three calls of the interface and gets the
    /// provider's answers and errors; the engine finds the provider by the
    /// name of the configuration.
    #[tokio::test]
    async fn the_client_calls_a_provider_over_its_socket() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let recorder = Recorder::default();
                let socket = serve(dir.path(), &recorder);
                let config: velarx_config::Config = toml::from_str(&format!(
                    "[[network.providers]]\nname = \"overlay\"\nsocket = \"{}\"\n",
                    socket.display()
                ))
                .unwrap();
                let providers = Providers::of_config(&config);
                assert!(providers.get("other").is_none());
                let client = providers.get("overlay").unwrap();
                let prepared = client.prepare("c1").await.unwrap();
                assert_eq!(prepared.devices[0].container, "eth1");
                assert_eq!(prepared.dns, Some(Ipv4Addr::new(10, 200, 1, 1)));
                let err = client.prepare("bad").await.unwrap_err();
                assert!(err.to_string().contains("no veth"), "{err}");
                let netns = std::fs::File::open("/proc/self/ns/net").unwrap();
                client.start("c1", "web", netns.into(), true).await.unwrap();
                client.stop("c1").await.unwrap();
                // idempotent: stopped already, and never started
                client.stop("c1").await.unwrap();
                client.stop("never").await.unwrap();
                assert_eq!(
                    *recorder.0.lock().unwrap(),
                    [
                        "prepare c1",
                        "prepare bad",
                        "start c1 web 1 true",
                        "stop c1",
                        "stop c1",
                        "stop never"
                    ]
                );
            })
            .await;
    }

    /// The providers that made the network of a container that is not made
    /// after all (another provider failed, or a later step of the create)
    /// are the ones told to undo it.
    #[tokio::test]
    async fn the_providers_that_prepared_are_the_ones_stopped() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let (good, refused) = (Recorder::default(), Recorder(Arc::default(), PROTO + 1));
                let (a, b) = (dir.path().join("a"), dir.path().join("b"));
                std::fs::create_dir(&a).unwrap();
                std::fs::create_dir(&b).unwrap();
                let config: velarx_config::Config = toml::from_str(&format!(
                    "[[network.providers]]\nname = \"good\"\nsocket = \"{}\"\n\
                     [[network.providers]]\nname = \"refused\"\nsocket = \"{}\"\n",
                    serve(&a, &good).display(),
                    serve(&b, &refused).display()
                ))
                .unwrap();
                let providers = Providers::of_config(&config);
                let mut prepared = Vec::new();
                let (name, _) = providers
                    .prepare(&["good", "refused"], "c1", &mut prepared)
                    .await
                    .unwrap_err();
                assert_eq!(
                    (name.as_str(), prepared.as_slice()),
                    ("refused", &["good".to_string()][..])
                );
                providers.stop(&prepared, "c1").await;
                assert_eq!(*good.0.lock().unwrap(), ["prepare c1", "stop c1"]);
                assert!(refused.0.lock().unwrap().is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn a_provider_that_is_not_running_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let client = ProviderClient::new(&dir.path().join("none.sock"));
        let err = client.stop("c1").await.unwrap_err();
        assert!(matches!(err, ClientError::Unreachable { .. }), "{err}");
    }
}
