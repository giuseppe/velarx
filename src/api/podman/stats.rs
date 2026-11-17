// SPDX-License-Identifier: Apache-2.0
//! The stats of containers: samples of what they use, as the records of
//! `ContainerStats` (velarx-shape lays out podman's ContainerStats, Docker's
//! StatsJSON and the reports of pods of them).

use super::error::{ApiError, ApiResult};
use super::events::now_nanos;
use super::lifecycle;
use crate::api::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use velarx_db::ContainerRecord;
use velarx_proto::workload::{InterfaceStats, StatsRecord};

fn host_memory() -> u64 {
    let si = rustix::system::sysinfo();
    (si.totalram as u64).saturating_mul(u64::from(si.mem_unit))
}

/// The CPU time of the host (all the CPUs), in ns.
fn host_cpu_ns() -> u64 {
    let Ok(stat) = std::fs::read_to_string("/proc/stat") else {
        return 0;
    };
    let tck = (rustix::param::clock_ticks_per_second()).max(1);
    let total: u64 = stat
        .lines()
        .next()
        .map(|l| {
            l.split_whitespace()
                .skip(1)
                .take(8)
                .filter_map(|v| v.parse::<u64>().ok())
                .sum()
        })
        .unwrap_or(0);
    total * (1_000_000_000 / tck)
}

/// The interfaces of the counters of the engine, by name.
fn interfaces(
    nets: &std::collections::BTreeMap<String, velarx_wire::wire::NetworkCounters>,
) -> Vec<InterfaceStats> {
    nets.iter()
        .map(|(name, n)| InterfaceStats {
            name: name.clone(),
            rx_bytes: n.rx_bytes,
            rx_packets: n.rx_packets,
            rx_errors: n.rx_errors,
            rx_dropped: n.rx_dropped,
            tx_bytes: n.tx_bytes,
            tx_packets: n.tx_packets,
            tx_errors: n.tx_errors,
            tx_dropped: n.tx_dropped,
        })
        .collect()
}

/// The CPUs the process may run on (its affinity: what a cpuset leaves it),
/// else those online.
fn usable_cpus(pid: impl TryInto<i32>) -> u64 {
    pid.try_into()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .and_then(|pid| rustix::thread::sched_getaffinity(Some(pid)).ok())
        .map(|set| u64::from(set.count()))
        .filter(|n| *n > 0)
        .unwrap_or_else(|| velarx_sys::system::online_cpus().max(1) as u64)
}

/// The record of a container that does not run: zeros.
fn zero(rec: &ContainerRecord) -> StatsRecord {
    StatsRecord {
        id: rec.id.clone(),
        name: rec.name.clone().unwrap_or_default(),
        ..Default::default()
    }
}

/// A sample of a container that runs (`size`: with what it wrote).
async fn sample_of(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    st: &lifecycle::Status,
    size: bool,
) -> ApiResult<StatsRecord> {
    if !st.alive() {
        return Err(
            ApiError::invalid_state("container is stopped").with_cause("container is stopped")
        );
    }
    let s = state
        .container_service
        .get_stats(&rec.id)
        .await
        .map_err(|e| ApiError::invalid_state(e.to_string()))?;
    let host = host_memory();
    let limit = s
        .memory_limit
        .filter(|l| *l > 0 && *l <= host)
        .unwrap_or(host);
    let written = if size {
        Some(super::archive::upper_usage(state, &rec.id).await)
    } else {
        None
    };
    let unsigned = |n: i64| n.max(0) as u64;
    Ok(StatsRecord {
        id: rec.id.clone(),
        name: rec.name.clone().unwrap_or_default(),
        running: true,
        time_ns: now_nanos(),
        started_ns: st.started_ns,
        cpu_nano: s.cpu_usage_ns,
        cpu_user_nano: s.cpu_user_ns,
        cpu_system_nano: s.cpu_system_ns,
        cpu_percent: 0.0,
        host_cpu_nano: host_cpu_ns(),
        online_cpus: usable_cpus(st.pid),
        cpu_periods: s.cpu_periods,
        cpu_throttled_periods: s.cpu_throttled_periods,
        cpu_throttled_nano: s.cpu_throttled_ns,
        mem_usage: s.memory_usage,
        mem_working_set: s.memory_working_set,
        mem_anon: s.memory_anon,
        mem_file: s.memory_file,
        mem_swap: s.memory_swap,
        mem_limit: limit,
        swap_limit: s.memory_swap_limit.unwrap_or(0),
        pressure: s.pressure,
        page_faults: s.page_faults,
        major_page_faults: s.major_page_faults,
        rw_bytes: written.map(|w| unsigned(w.0)),
        rw_inodes: written.map(|w| unsigned(w.1)),
        block_read: s.io_read_bytes,
        block_write: s.io_write_bytes,
        networks: interfaces(&s.networks),
        pids: u64::from(s.pids),
    })
}

/// The samples of the containers a call of `ContainerStats` asked for, one
/// after another: the CPU use of each is since its sample before.
pub struct Sampler {
    state: Arc<AppState>,
    names: Vec<String>,
    all: bool,
    size: bool,
    /// The time and the CPU time of the sample before, by id
    before: HashMap<String, (i64, u64)>,
}

impl Sampler {
    /// The containers `names` (none: those that run, all of them with
    /// `all`, those that do not as zeros); `size`: with what they wrote.
    pub fn new(state: &Arc<AppState>, names: Vec<String>, all: bool, size: bool) -> Self {
        Self {
            state: state.clone(),
            names,
            all,
            size,
            before: HashMap::new(),
        }
    }

    /// A sample of each.  A container named that does not run has zeros;
    /// one of all that cannot be read is left out.
    pub async fn sample(&mut self) -> ApiResult<Vec<StatsRecord>> {
        let state = &self.state;
        // (the state of each is told once, from what the runtime said when
        // the container was found)
        let mut recs = Vec::new();
        if self.names.is_empty() {
            for (r, asked) in state.container_service.list_observed(self.all).await? {
                let status = lifecycle::status_from(state, &r, asked).await;
                if self.all || status.alive() {
                    recs.push((r, status));
                }
            }
        } else {
            for n in &self.names {
                let (r, asked) = lifecycle::resolve_observed(state, n).await?;
                let status = lifecycle::status_from(state, &r, asked).await;
                recs.push((r, status));
            }
        }
        let mut out = Vec::new();
        for (rec, status) in &recs {
            if (self.all || !self.names.is_empty()) && !status.alive() {
                out.push(zero(rec));
                continue;
            }
            match sample_of(state, rec, status, self.size).await {
                Ok(mut s) => {
                    s.cpu_percent = match self.before.get(&s.id) {
                        Some((time, cpu)) if s.time_ns > *time => {
                            s.cpu_nano.saturating_sub(*cpu) as f64 / (s.time_ns - time) as f64
                                * 100.0
                        }
                        _ if s.started_ns > 0 && s.time_ns > s.started_ns => {
                            s.cpu_nano as f64 / (s.time_ns - s.started_ns) as f64 * 100.0
                        }
                        _ => 0.0,
                    };
                    self.before.insert(s.id.clone(), (s.time_ns, s.cpu_nano));
                    out.push(s);
                }
                Err(e) if self.names.is_empty() => tracing::debug!("stats: {e}"),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cpus_of_a_process_are_those_of_its_affinity() {
        let me = std::process::id();
        let set = rustix::thread::sched_getaffinity(None).unwrap();
        assert_eq!(usable_cpus(me as i32), u64::from(set.count()));
        // (no process: the CPUs online)
        assert!(usable_cpus(0) >= 1);
    }

    #[test]
    fn net_dev_gives_the_interfaces_but_lo() {
        let text = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n    lo: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n  eth0: 100 2 3 4 0 0 0 0 200 5 6 7 0 0 0 0\n  eth1: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n";
        let n = interfaces(&velarx_wire::wire::NetworkCounters::parse_net_dev(text));
        assert_eq!(n.len(), 2);
        assert_eq!(
            (
                n[0].name.as_str(),
                n[0].rx_bytes,
                n[0].tx_bytes,
                n[0].tx_dropped
            ),
            ("eth0", 100, 200, 7)
        );
        assert_eq!(n[1].name, "eth1");
    }
}
