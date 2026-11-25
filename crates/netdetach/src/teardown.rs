// SPDX-License-Identifier: Apache-2.0
//! The release of the network of a container that ended: what
//! `ContainerNetworks::teardown` of the engine did, as one piece of code the
//! monitor of the container runs too.
//!
//! [`Detach::begin`] does what a confined thread may not (the bind mount of
//! the pool, the exec of the CNI plugins); [`Detach::finish`] the rest: pasta,
//! the port forwarder, the bridge, its firewall rules and DNS records, the
//! rootless namespace, the record of the namespace and the providers.  Every
//! step is idempotent and best effort: the first error is kept and the rest
//! is done.

use crate::input::bridge_input;
use crate::provider::{stop_blocking, ProviderRef};
use crate::spec::{read_spec, Mode, NetSpec};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
use velarx_config::BridgeConfig;
use velarx_db::sync::Access;
use velarx_netkernel::bridge::{self, BridgeOptions, NetnsFate};
use velarx_netkernel::cni::CniConfig;
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_netkernel::netns::{Netns, Records};
use velarx_wire::request::NetworkMode;

/// The interface of a container on a CNI network.
pub const CNI_IFNAME: &str = "eth0";

/// What the release of a container's network needs, beside the store: built
/// once by the engine and serialised into the plan of the monitor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Detach {
    /// `<state>/networks`
    pub run: PathBuf,
    /// `<state>/netns-pool`
    pub pool_dir: PathBuf,
    /// The run root
    pub state_dir: PathBuf,
    /// The store's database (the namespaces tables)
    pub db: PathBuf,
    /// Where the bridges live: `netns` is none, the rootless one is found
    /// per call
    pub bridge: BridgeOptions,
    /// The network of the configuration
    pub cfg: BridgeConfig,
    pub cni: CniConfig,
    /// The links of the namespace of the engine are not its own: bridges
    /// live in the rootless network namespace
    pub rootless: bool,
    /// The rootless network namespace can be made
    pub rootless_netns: bool,
    /// The providers `Stop` is sent to
    pub providers: Vec<ProviderRef>,
}

/// What [`Detach::begin`] did and [`Detach::finish`] goes on from.
pub struct Begun {
    id: String,
    /// None: no setup is recorded (or it cannot be read)
    spec: Option<NetSpec>,
    ns: Option<Netns>,
    /// The first error so far
    result: NetworkResult<()>,
    pooled: bool,
    /// What the store said when the setup could not be read from it: nothing
    /// of the network is undone (its record stays, the next release redoes
    /// it), the providers are told
    aborted: Option<NetworkError>,
    /// The processes to stop, found while the caller could read their
    /// `/proc` (a confined thread cannot)
    pasta: velarx_netkernel::pasta::Found,
    forwarder: Option<std::os::fd::OwnedFd>,
    rootless: Option<crate::rootless::Held>,
}

/// What the release did.
#[derive(Debug, Default)]
pub struct Detached {
    /// The namespace went to the pool
    pub pooled: bool,
    /// The providers that could not be told
    pub providers_failed: Vec<String>,
}

pub fn check_id(id: &str) -> NetworkResult<()> {
    if id.is_empty()
        || id.starts_with('.')
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(NetworkError::InvalidConfig(format!(
            "invalid container id `{id}`"
        )));
    }
    Ok(())
}

/// The CNI attachment of the container `id` with the namespace `netns`.
pub fn cni_attachment(
    id: &str,
    spec: &NetSpec,
    netns: Option<&Path>,
) -> NetworkResult<velarx_netkernel::cni::Attachment> {
    let pod = |k: &str| spec.cni_pod.get(k).cloned().unwrap_or_default();
    let mut port_mappings = Vec::new();
    for p in spec.port_specs()? {
        for i in 0..p.range.max(1) {
            port_mappings.push(velarx_netkernel::cni::PortMapping {
                host_port: p.host_port + i,
                container_port: p.container_port + i,
                protocol: p.proto.as_str().to_string(),
                host_ip: p.host_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            });
        }
    }
    Ok(velarx_netkernel::cni::Attachment {
        container_id: id.to_string(),
        netns: netns.map(Path::to_path_buf),
        ifname: CNI_IFNAME.to_string(),
        pod_name: pod("io.kubernetes.pod.name"),
        pod_namespace: pod("io.kubernetes.pod.namespace"),
        pod_uid: pod("io.kubernetes.pod.uid"),
        port_mappings,
        ip_ranges: spec.cni_ip_ranges.clone(),
        annotations: spec
            .cni_annotations
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
        ..Default::default()
    })
}

impl Detach {
    pub fn pasta_file(&self, id: &str, ext: &str) -> PathBuf {
        self.run.join("pasta").join(format!("{id}.{ext}"))
    }

    pub fn portfwd_pid(&self, id: &str) -> PathBuf {
        self.run.join("portfwd").join(format!("{id}.pid"))
    }

    pub fn records(&self) -> Records {
        Records::new(&self.db)
    }

    /// The options to tear down with: None when there is nothing (no
    /// rootless network namespace yet).
    pub fn opts_if_any(&self) -> NetworkResult<Option<BridgeOptions>> {
        let mut o = self.bridge.clone();
        if self.rootless {
            if !self.rootless_netns {
                return Ok(None);
            }
            let Some(ns) = velarx_netkernel::rootless_netns::path_in(
                &self.run,
                &self.db,
                velarx_nsid::tree::members,
            )?
            else {
                return Ok(None);
            };
            o.netns = Some(ns);
        }
        Ok(Some(o))
    }

    /// The namespace of the container: the one the caller holds, else the
    /// one its record names (opened through a process of the container).
    fn namespace(&self, a: &impl Access, id: &str, held: Option<Netns>) -> Option<Netns> {
        if held.is_some() {
            return held;
        }
        let owned = id.to_string();
        let c = a.call(move |c| velarx_db::get_container(c, &owned)).ok()?;
        let pid = c.pid.filter(|_| c.state.is_alive());
        let pids: Vec<i32> = pid.into_iter().collect();
        // (no record: a container no network was set up for)
        self.records()
            .open(id, &pids)
            .or_else(|| pid.and_then(|p| Netns::of_process(p).ok()))
    }

    /// The first half of the release: what a confined thread may not do.
    /// `held` is the namespace as the caller holds it (the monitor's own
    /// descriptor, the engine's held one); none: the recorded one is opened.
    pub fn begin(&self, a: &impl Access, id: &str, held: Option<Netns>) -> NetworkResult<Begun> {
        check_id(id)?;
        // A setup that cannot be read is the result, but what needs none of
        // it is still undone (its pasta, the forwarder, the namespace): the
        // next release could not read it either.
        let (spec, mut result) = match read_spec(a, id) {
            Ok(spec) => (spec, Ok(())),
            Err(e @ (NetworkError::InvalidConfig(_) | NetworkError::Unreadable(_))) => {
                (None, Err(e))
            }
            Err(e) => {
                return Ok(Begun {
                    id: id.to_string(),
                    spec: None,
                    ns: None,
                    result: Ok(()),
                    pooled: false,
                    aborted: Some(e),
                    pasta: Default::default(),
                    forwarder: None,
                    rootless: None,
                })
            }
        };
        let ns = self.namespace(a, id, held);
        let mut pooled = false;
        let mode = spec.as_ref().map(|s| s.mode).unwrap_or_default();
        let shareable = spec.as_ref().is_some_and(|s| s.shareable);
        if ns.is_some() || self.records().exists(id) {
            let pin = ns.as_ref().map(Netns::path);
            if mode == Mode::Bridge && shareable {
                if let Some(pin) = &pin {
                    match self.pool_return(a, id, pin) {
                        Ok(true) => {
                            self.forget(id);
                            pooled = true;
                        }
                        Ok(false) => {}
                        Err(e) => debug!("the namespace of {id} is not pooled: {e}"),
                    }
                }
            }
            if !pooled && mode == Mode::Cni {
                result = cni_attachment(
                    id,
                    spec.as_ref().unwrap_or(&NetSpec::default()),
                    pin.as_deref(),
                )
                .and_then(|attachment| {
                    velarx_netkernel::cni::del(&self.cni, &attachment)
                        .map_err(|e| NetworkError::Cni(e.to_string()))
                });
            }
        }
        let wait = spec.as_ref().is_none_or(|s| !s.ports.is_empty());
        let pasta = velarx_netkernel::pasta::find(&self.pasta_file(id, "pid"), wait);
        let fwd = self.portfwd_pid(id);
        let forwarder = fwd
            .exists()
            .then(|| velarx_netkernel::portfwd::find(&fwd, id))
            .flatten();
        // (the rest of the release goes on without it: what is found of the
        // rootless namespace then is found later, if it can be)
        let rootless = if mode == Mode::Bridge && !pooled && self.rootless && self.rootless_netns {
            match self.hold() {
                Ok(held) => Some(held),
                Err(e) => {
                    result = result.and(Err(e));
                    None
                }
            }
        } else {
            None
        };
        Ok(Begun {
            id: id.to_string(),
            spec,
            ns,
            result,
            pooled,
            aborted: None,
            pasta,
            forwarder,
            rootless,
        })
    }

    fn forget(&self, id: &str) {
        if let Err(e) = self.records().forget(id) {
            debug!("cannot forget the network namespace of {id}: {e}");
        }
    }

    /// The rest of the release.  `on_stop_pasta` runs before the pasta of
    /// the rootless namespace is stopped (the engine ends its watch).  The
    /// providers are told whatever the rest came to.
    pub fn finish(
        &self,
        a: &impl Access,
        begun: Begun,
        on_stop_pasta: &dyn Fn(),
    ) -> NetworkResult<Detached> {
        let id = begun.id.clone();
        let released = self.release_begun(a, begun, on_stop_pasta);
        let providers_failed = self.stop_providers(a, &id);
        released.map(|pooled| Detached {
            pooled,
            providers_failed,
        })
    }

    /// [`Self::finish`] but the providers: whether the namespace went to the
    /// pool.
    fn release_begun(
        &self,
        a: &impl Access,
        begun: Begun,
        on_stop_pasta: &dyn Fn(),
    ) -> NetworkResult<bool> {
        let Begun {
            id,
            spec,
            ns,
            mut result,
            pooled,
            aborted,
            pasta,
            forwarder,
            rootless,
        } = begun;
        if let Some(e) = aborted {
            return Err(e);
        }
        // (a pasta that publishes ports is waited for: it holds them)
        let wait = spec.as_ref().is_none_or(|s| !s.ports.is_empty());
        let mode = spec.as_ref().map(|s| s.mode).unwrap_or_default();
        let shareable = spec.as_ref().is_some_and(|s| s.shareable);
        velarx_netkernel::pasta::stop_found(&self.pasta_file(&id, "pid"), pasta, wait);
        let _ = std::fs::remove_file(self.pasta_file(&id, "log"));
        let fwd = self.portfwd_pid(&id);
        if fwd.exists() {
            velarx_netkernel::portfwd::stop_found(&fwd, forwarder);
        }
        if pooled {
            return Ok(true);
        }
        if (ns.is_some() || self.records().exists(&id)) && mode == Mode::Bridge {
            // (the namespace of a shareable one may be held by the
            // containers that joined it, as that of any container by one
            // that runs with `--network container:ID`)
            let fate = if shareable || self.joined_by_live(a, &id) {
                NetnsFate::Stays
            } else {
                NetnsFate::Released
            };
            // (an error of the database is the result, and the namespace
            // stays recorded: without what the database has of its
            // attachments nothing of the host side is undone yet, which the
            // next release does; a record that cannot be read is the result
            // too, but no later release reads it: the namespace goes, with
            // the container's end of its links)
            let input = match bridge_input(a, &self.cfg, &id, None) {
                Ok(input) => input,
                Err(e @ NetworkError::InvalidConfig(_)) => {
                    result = Err(e);
                    None
                }
                Err(e) => return Err(e),
            };
            let opts = match &rootless {
                // (the namespace of the rootless bridges, held open: its
                // path is the descriptor's, which any thread can open)
                Some(held) => Ok(held.ns.as_ref().map(|found| {
                    let mut o = self.bridge.clone();
                    o.netns = Some(PathBuf::from(velarx_sys::fd::proc_raw(
                        std::os::fd::AsRawFd::as_raw_fd(&found.ns),
                    )));
                    o
                })),
                None => self.opts_if_any(),
            };
            result = match (opts, input) {
                (_, None) => result,
                (Ok(Some(opts)), Some(input)) => {
                    let path = ns.as_ref().map(Netns::path);
                    bridge::teardown(&opts, path.as_deref(), &input, fate)
                }
                (Err(e), _) => Err(e),
                _ => Ok(()),
            };
        }
        self.forget(&id);
        if mode == Mode::Bridge {
            // (a monitor that holds the namespace lets go of it: this
            // process, when it is one; no record for any other)
            if self.rootless && self.rootless_netns {
                if let Err(e) = velarx_netkernel::rootless_netns::remove_monitor_holder(
                    &self.db,
                    std::process::id() as i32,
                ) {
                    tracing::debug!("the monitor is still a holder of the namespace: {e}");
                }
            }
            match rootless {
                Some(held) => self.release_held(held, on_stop_pasta),
                None => self.release_if_unused(on_stop_pasta),
            }
        }
        result.map(|()| false)
    }

    /// Whether a container that is alive joins the network namespace of the
    /// container `id` (`--network container:ID`): the namespace outlives
    /// it, so its interfaces are deleted, not left to the kernel.  A store
    /// that cannot be read says yes: the interfaces are deleted then too.
    fn joined_by_live(&self, a: &impl Access, id: &str) -> bool {
        let owned = id.to_string();
        a.call(move |c| {
            let this = velarx_db::get_container(c, &owned)?;
            let name = this.name.unwrap_or_default();
            for dependent in velarx_db::container_dependents(c, &this.id, &name)? {
                let dependent = velarx_db::get_container(c, &dependent)?;
                let joins = serde_json::from_str::<JoinedNetwork>(&dependent.config)
                    .is_ok_and(|j| matches!(j.network_mode, NetworkMode::Container(_)));
                if joins && dependent.state.is_alive() {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap_or(true)
    }

    /// `Stop` of each provider the container's networks name; a failure is
    /// logged, never fatal.
    fn stop_providers(&self, a: &impl Access, id: &str) -> Vec<String> {
        let mut failed = Vec::new();
        if self.providers.is_empty() {
            return failed;
        }
        let owned = id.to_string();
        let Ok(container) = a.call(move |c| velarx_db::get_container(c, &owned)) else {
            return failed;
        };
        let Ok(config) = serde_json::from_str::<ProviderNames>(&container.config) else {
            return failed;
        };
        let names = crate::provider::names_of(&config.network_mode, &config.networks);
        for p in self
            .providers
            .iter()
            .filter(|p| names.contains(&p.name.as_str()))
        {
            if let Err(e) = stop_blocking(&p.socket, id) {
                warn!(
                    "Network provider {} could not stop the network of {id}: {e}",
                    p.name
                );
                failed.push(p.name.clone());
            }
        }
        failed
    }

    /// Both halves in a row (the engine's paths).
    pub fn release(
        &self,
        a: &impl Access,
        id: &str,
        held: Option<Netns>,
        on_stop_pasta: &dyn Fn(),
    ) -> NetworkResult<Detached> {
        let begun = self.begin(a, id, held)?;
        self.finish(a, begun, on_stop_pasta)
    }
}

/// The part of a container's stored configuration that says whether it
/// joins the network of another container.
#[derive(Deserialize)]
struct JoinedNetwork {
    #[serde(default)]
    network_mode: NetworkMode,
}

/// The part of a container's stored configuration that names its providers.
#[derive(Deserialize)]
struct ProviderNames {
    #[serde(default)]
    network_mode: NetworkMode,
    #[serde(default)]
    networks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn detach(dir: &Path) -> Detach {
        let run = dir.join("networks");
        Detach {
            run: run.clone(),
            pool_dir: dir.join("netns-pool"),
            state_dir: dir.to_path_buf(),
            db: dir.join("db.sqlite"),
            bridge: BridgeOptions {
                state_dir: run,
                firewall: velarx_netkernel::firewall::Firewall {
                    table: "velarx".into(),
                },
                dns_exe: "velarx".into(),
                netns: None,
            },
            cfg: velarx_config::Config::default().network.bridge,
            cni: CniConfig::default(),
            rootless: false,
            rootless_netns: false,
            providers: vec![ProviderRef {
                name: "p".into(),
                socket: "/run/p.sock".into(),
            }],
        }
    }

    #[test]
    fn what_releases_a_network_travels_in_a_plan() {
        let dir = tempfile::tempdir().unwrap();
        let d = detach(dir.path());
        let back: Detach = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back.run, d.run);
        assert_eq!(back.providers, d.providers);
        assert_eq!(back.cfg.default_bridge, d.cfg.default_bridge);
    }

    #[test]
    fn an_id_is_checked_before_anything() {
        for bad in ["", ".x", "a/b", "a b"] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
        assert!(check_id("abc-DEF_09").is_ok());
    }

    #[test]
    fn a_container_the_database_does_not_know_is_released_with_nothing_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let d = detach(dir.path());
        let db = dir.path().join("db.sqlite");
        {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let database = velarx_db::Database::open(&db).await.unwrap();
                database.close().await.unwrap();
            });
        }
        let store = velarx_db::sync::Store::open(&db).unwrap();
        let done = d.release(&store, "c1", None, &|| {}).unwrap();
        assert!(!done.pooled);
        assert!(done.providers_failed.is_empty());
    }

    /// The interfaces of a container are deleted, not left to the kernel,
    /// when a container that is alive has its network namespace.
    #[test]
    fn a_live_container_that_joins_the_network_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let d = detach(dir.path());
        let db = dir.path().join("db.sqlite");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            velarx_db::Database::open(&db)
                .await
                .unwrap()
                .close()
                .await
                .unwrap();
        });
        let store = velarx_db::sync::Store::open(&db).unwrap();
        store
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, name, image_id, config, state, created_at) VALUES
                       ('a', 'an', 'i', '{}', 'exited', 'now'),
                       ('b', 'bn', 'i', '{\"network_mode\":\"container:an\"}', 'running', 'now'),
                       ('c', 'cn', 'i', '{\"options\":{\"pid_ns\":\"container:a\"}}', 'running', 'now'),
                       ('e', 'en', 'i', '{\"network_mode\":\"container:a\"}', 'exited', 'now');
                     INSERT INTO container_deps (container_id, target) VALUES ('b','an'), ('c','a'), ('e','a');",
                )?;
                Ok(())
            })
            .unwrap();
        assert!(d.joined_by_live(&store, "a"));
        // (only a container that has ended joins it, or only its pid
        // namespace)
        store
            .call(|c| {
                c.execute_batch("UPDATE containers SET state = 'exited' WHERE id = 'b'")?;
                Ok(())
            })
            .unwrap();
        assert!(!d.joined_by_live(&store, "a"));
    }

    #[test]
    fn the_forwarder_of_a_stale_pid_file_is_not_signalled_and_its_file_goes() {
        let dir = tempfile::tempdir().unwrap();
        let d = detach(dir.path());
        let db = dir.path().join("db.sqlite");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            velarx_db::Database::open(&db)
                .await
                .unwrap()
                .close()
                .await
                .unwrap();
        });
        // (our own pid: not a forwarder of c1, so it is left alone)
        let fwd = d.portfwd_pid("c1");
        std::fs::create_dir_all(fwd.parent().unwrap()).unwrap();
        std::fs::write(&fwd, std::process::id().to_string()).unwrap();
        let store = velarx_db::sync::Store::open(&db).unwrap();
        d.release(&store, "c1", None, &|| {}).unwrap();
        assert!(!fwd.exists());
    }
}
