// SPDX-License-Identifier: Apache-2.0
//! The restart policy, applied by the monitor: a container that exits is
//! started again by its monitor, whether the daemon runs or not.
//!
//! A restart is a new container of the runtime in the same bundle, with the
//! root file system the monitor keeps mounted.  Its network namespace (and
//! its user namespace when it has one of its own) are those of the first
//! run, which the monitor keeps open: the network the daemon set up for the
//! container is still there, and nothing has to set it up again.

use serde::{Deserialize, Serialize};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use velarx_wire::monitor::proto::ExitInfo;
use velarx_wire::monitor::proto::{RestartPolicy, RestartSettings};

/// How long a run has to last to count as a success: the wait before the
/// next restart starts again from the shortest.  The restarts made still
/// count against the limit of the policy.
pub const RESET_AFTER: Duration = Duration::from_secs(10);

/// The restarts made by the restart policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct Restarts {
    /// All of them: what `on-failure:N` limits and what is reported.
    pub total: u32,
    /// Those since the last run that lasted `RESET_AFTER`: what the wait
    /// before the next restart grows with.
    since_success: u32,
}

impl Restarts {
    /// The restarts of a monitor that starts after `total` of them (all of
    /// them since a success, as nothing says otherwise).
    pub fn after(total: u32) -> Self {
        Restarts {
            total,
            since_success: total,
        }
    }

    /// The run that ended lasted `ran`.
    pub fn ended(&mut self, ran: Duration) {
        if ran >= RESET_AFTER {
            self.since_success = 0;
        }
    }

    /// Count a restart and return the wait before it.
    pub fn count(&mut self) -> Duration {
        let wait = delay(self.since_success);
        self.since_success += 1;
        self.total += 1;
        wait
    }
}

/// What the monitor does when the container exits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestartConfig {
    /// The restart policy of the container.
    #[serde(default)]
    pub policy: Option<RestartSettings>,
    /// The restarts made before this monitor started.
    #[serde(default)]
    pub count: u32,
}

impl RestartConfig {
    /// Whether an exit of the container can be followed by a restart.
    pub fn possible(&self, health_restarts: bool) -> bool {
        health_restarts
            || self
                .policy
                .as_ref()
                .is_some_and(|p| p.policy != RestartPolicy::No)
    }
}

/// Whether the restart policy starts the container again after this exit,
/// `restarts` restarts made so far.
pub fn should_restart(cfg: &RestartConfig, info: &ExitInfo, restarts: u32) -> bool {
    if info.stop_requested {
        return false;
    }
    if info.health_restart {
        return true;
    }
    let Some(p) = &cfg.policy else {
        return false;
    };
    match p.policy {
        RestartPolicy::Always | RestartPolicy::UnlessStopped => true,
        RestartPolicy::OnFailure => {
            info.code != 0 && (p.max_retries == 0 || restarts < p.max_retries)
        }
        RestartPolicy::No => false,
    }
}

/// The wait before the next restart: it doubles from 100 ms up to 5 s.
pub fn delay(restarts: u32) -> Duration {
    Duration::from_millis(if restarts < 6 {
        100u64 << restarts
    } else {
        5000
    })
}

/// The namespaces of the first run that the next runs join: the network
/// and user namespaces it made, and every namespace it joined (of another
/// container, of a pod: the process that held them then may be gone or
/// its pid reused by now).
#[derive(Default)]
pub struct Pinned {
    /// `(OCI type, namespace)`
    ns: Vec<(String, OwnedFd)>,
    /// The user namespace is joined: the spec's mappings are its own.
    user: bool,
}

/// The `/proc/PID/ns` name of an OCI namespace type.
fn proc_name(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "network" => "net",
        "user" => "user",
        "ipc" => "ipc",
        "uts" => "uts",
        "pid" => "pid",
        "cgroup" => "cgroup",
        "time" => "time",
        _ => return None,
    })
}

/// The namespaces of a spec to pin: those it joins (a path), except the
/// mount namespace, and the network and user namespaces it makes.
fn to_pin(spec: &serde_json::Value) -> Vec<String> {
    let Some(list) = spec.pointer("/linux/namespaces").and_then(|n| n.as_array()) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|ns| {
            let kind = ns.get("type")?.as_str()?;
            let joined = ns
                .get("path")
                .and_then(|p| p.as_str())
                .is_some_and(|p| !p.is_empty());
            (joined || matches!(kind, "network" | "user"))
                .then_some(kind)
                .filter(|k| proc_name(k).is_some())
                .map(str::to_string)
        })
        .collect()
}

/// Keep the namespaces of the spec's container, whose process is `pid`.
pub fn pin(spec: &serde_json::Value, pid: i32) -> io::Result<Pinned> {
    let mut out = Pinned::default();
    for kind in to_pin(spec) {
        let Some(name) = proc_name(&kind) else {
            continue;
        };
        let fd: OwnedFd = std::fs::File::open(format!("/proc/{pid}/ns/{name}"))?.into();
        out.user |= kind == "user";
        out.ns.push((kind, fd));
    }
    Ok(out)
}

impl Pinned {
    pub fn is_empty(&self) -> bool {
        self.ns.is_empty()
    }

    /// The spec of a restart: the pinned namespaces are joined through the
    /// descriptors of the process `holder`; a user namespace that is joined
    /// has its mappings already.
    pub fn restart_spec(&self, spec: &serde_json::Value, holder: u32) -> serde_json::Value {
        let mut spec = spec.clone();
        if let Some(list) = spec
            .pointer_mut("/linux/namespaces")
            .and_then(|n| n.as_array_mut())
        {
            for ns in list.iter_mut() {
                let Some(kind) = ns.get("type").and_then(|t| t.as_str()) else {
                    continue;
                };
                let Some((_, fd)) = self.ns.iter().find(|(k, _)| k == kind) else {
                    continue;
                };
                let path = format!("/proc/{holder}/fd/{}", fd.as_raw_fd());
                if let Some(obj) = ns.as_object_mut() {
                    obj.insert("path".into(), path.into());
                }
            }
        }
        if self.user {
            if let Some(linux) = spec.get_mut("linux").and_then(|l| l.as_object_mut()) {
                linux.remove("uidMappings");
                linux.remove("gidMappings");
            }
        }
        spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: i32) -> ExitInfo {
        ExitInfo {
            code,
            finished_ns: 0,
            oom: false,
            health_restart: false,
            stop_requested: false,
            timed_out: false,
            checkpointed: false,
            started_ns: None,
            remove: false,
            volumes: false,
        }
    }

    fn policy(name: &str, max: u32) -> RestartConfig {
        RestartConfig {
            policy: Some(RestartSettings {
                policy: RestartPolicy::from_word(name).unwrap(),
                max_retries: max,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_restart_policies() {
        assert!(!should_restart(&RestartConfig::default(), &exit(1), 0));
        assert!(!should_restart(&policy("no", 0), &exit(1), 0));
        assert!(should_restart(&policy("always", 0), &exit(0), 9));
        assert!(should_restart(&policy("unless-stopped", 0), &exit(0), 9));
        let on_failure = policy("on-failure", 3);
        assert!(!should_restart(&on_failure, &exit(0), 0));
        assert!(should_restart(&on_failure, &exit(2), 2));
        assert!(!should_restart(&on_failure, &exit(2), 3));
        assert!(should_restart(&policy("on-failure", 0), &exit(2), 100));
    }

    #[test]
    fn a_long_run_shortens_the_wait_but_not_the_limit() {
        let cfg = policy("on-failure", 2);
        let mut restarts = Restarts::after(0);
        let mut waits = Vec::new();
        for _ in 0..5 {
            restarts.ended(RESET_AFTER + Duration::from_secs(1));
            if !should_restart(&cfg, &exit(1), restarts.total) {
                break;
            }
            waits.push(restarts.count());
        }
        assert_eq!(restarts.total, 2);
        assert_eq!(waits, [delay(0), delay(0)]);
        // short runs make the wait grow
        restarts.ended(Duration::from_secs(1));
        assert_eq!(restarts.count(), delay(0));
        restarts.ended(Duration::from_secs(1));
        assert_eq!(restarts.count(), delay(1));
        // a new monitor goes on from the restarts made
        assert_eq!(Restarts::after(3).count(), delay(3));
    }

    #[test]
    fn a_stop_ends_the_policy_and_an_unhealthy_container_restarts_regardless() {
        let mut stopped = exit(0);
        stopped.stop_requested = true;
        assert!(!should_restart(&policy("always", 0), &stopped, 0));
        let mut unhealthy = exit(137);
        unhealthy.health_restart = true;
        assert!(should_restart(&RestartConfig::default(), &unhealthy, 0));
        unhealthy.stop_requested = true;
        assert!(!should_restart(&RestartConfig::default(), &unhealthy, 0));
    }

    #[test]
    fn restarts_are_possible_with_a_policy_or_a_health_restart() {
        assert!(!RestartConfig::default().possible(false));
        assert!(RestartConfig::default().possible(true));
        assert!(!policy("no", 0).possible(false));
        assert!(policy("on-failure", 2).possible(false));
    }

    #[test]
    fn the_delay_grows_and_stops_growing() {
        let ms: Vec<u128> = (0..8).map(|n| delay(n).as_millis()).collect();
        assert_eq!(ms, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
    }

    #[test]
    fn the_namespaces_to_pin_are_found() {
        let spec = serde_json::json!({"linux": {"namespaces": [
            {"type": "pid"}, {"type": "network"}, {"type": "user", "path": "/proc/1/ns/user"},
            {"type": "mount"}, {"type": "ipc", "path": "/proc/9/ns/ipc"},
            {"type": "mount", "path": "/x"}, {"type": "uts", "path": ""}
        ]}});
        assert_eq!(to_pin(&spec), ["network", "user", "ipc"]);
        assert!(to_pin(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn a_restart_joins_the_pinned_namespaces() {
        let spec = serde_json::json!({"linux": {
            "namespaces": [{"type": "network"}, {"type": "user"}, {"type": "ipc"},
                           {"type": "uts", "path": "/x"}],
            "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
        }});
        let pinned = pin(&spec, std::process::id() as i32).unwrap();
        assert!(!pinned.is_empty());
        let fd_of = |k: &str| {
            pinned
                .ns
                .iter()
                .find(|(kind, _)| kind == k)
                .map(|(_, fd)| fd.as_raw_fd())
                .unwrap()
        };
        let (net, user, uts) = (fd_of("network"), fd_of("user"), fd_of("uts"));
        let out = pinned.restart_spec(&spec, 42);
        let ns = out.pointer("/linux/namespaces").unwrap();
        assert_eq!(ns[0]["path"], format!("/proc/42/fd/{net}"));
        assert_eq!(ns[1]["path"], format!("/proc/42/fd/{user}"));
        // a new IPC namespace for each run
        assert!(ns[2].get("path").is_none());
        // the one joined then, whatever its path says now
        assert_eq!(ns[3]["path"], format!("/proc/42/fd/{uts}"));
        assert!(out.pointer("/linux/uidMappings").is_none());
        assert!(out.pointer("/linux/gidMappings").is_none());

        // Only the network: the mappings stay.
        let spec = serde_json::json!({"linux": {
            "namespaces": [{"type": "network"}],
            "uidMappings": []
        }});
        let pinned = pin(&spec, std::process::id() as i32).unwrap();
        assert!(pinned
            .restart_spec(&spec, 1)
            .pointer("/linux/uidMappings")
            .is_some());
        assert!(Pinned::default().is_empty());
    }
}
