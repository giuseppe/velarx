// SPDX-License-Identifier: Apache-2.0
//! The stats of containers: podman's ContainerStats (and its report of
//! containers), Docker's StatsJSON and podman's PodStatsReport.

use crate::time::rfc3339;
use serde_json::{json, Map, Value};
use velarx_proto::workload::{InterfaceStats, StatsRecord};

fn rx(s: &StatsRecord) -> u64 {
    s.networks.iter().map(|n| n.rx_bytes).sum()
}

fn tx(s: &StatsRecord) -> u64 {
    s.networks.iter().map(|n| n.tx_bytes).sum()
}

/// How long the container has run when the sample was read.
fn up(s: &StatsRecord) -> i64 {
    if s.started_ns > 0 && s.time_ns > s.started_ns {
        s.time_ns - s.started_ns
    } else {
        0
    }
}

fn mem_percent(s: &StatsRecord) -> f64 {
    if s.mem_limit > 0 {
        s.mem_usage as f64 / s.mem_limit as f64 * 100.0
    } else {
        0.0
    }
}

/// podman's network stats (define.ContainerNetworkStats), by interface;
/// null without one.
fn libpod_networks(networks: &[InterfaceStats]) -> Value {
    if networks.is_empty() {
        return Value::Null;
    }
    let out: Map<String, Value> = networks
        .iter()
        .map(|n| {
            let counters = json!({
                "RxBytes": n.rx_bytes, "RxPackets": n.rx_packets,
                "RxErrors": n.rx_errors, "RxDropped": n.rx_dropped,
                "TxBytes": n.tx_bytes, "TxPackets": n.tx_packets,
                "TxErrors": n.tx_errors, "TxDropped": n.tx_dropped,
            });
            (n.name.clone(), counters)
        })
        .collect();
    Value::Object(out)
}

/// podman's define.ContainerStats.
pub fn libpod(s: &StatsRecord) -> Value {
    let up = up(s);
    let avg = if up > 0 {
        s.cpu_nano as f64 / up as f64 * 100.0
    } else {
        0.0
    };
    json!({
        "AvgCPU": avg,
        "ContainerID": s.id,
        "Name": s.name,
        "PerCPU": null,
        "CPU": s.cpu_percent,
        "CPUNano": s.cpu_nano,
        "CPUSystemNano": s.cpu_system_nano,
        "SystemNano": s.time_ns,
        "MemUsage": s.mem_usage,
        "MemLimit": s.mem_limit,
        "MemPerc": mem_percent(s),
        "NetInput": rx(s),
        "NetOutput": tx(s),
        "BlockInput": s.block_read,
        "BlockOutput": s.block_write,
        "PIDs": s.pids,
        "MemWorkingSet": s.mem_working_set,
        "PageFaults": s.page_faults,
        "MajorPageFaults": s.major_page_faults,
        "MemRss": s.mem_anon,
        "SwapUsage": s.mem_swap,
        "SwapLimit": s.swap_limit,
        "Pressure": serde_json::to_value(&s.pressure).unwrap_or_default(),
        "RwBytes": s.rw_bytes,
        "RwInodes": s.rw_inodes,
        "UpTime": up,
        "Duration": s.cpu_nano,
        "Network": libpod_networks(&s.networks),
    })
}

/// podman's report of `GET /containers/stats`: the containers of a sample.
pub fn libpod_report(stats: &[StatsRecord]) -> Value {
    json!({"Error": null, "Stats": stats.iter().map(libpod).collect::<Vec<_>>()})
}

/// The CPU stats of Docker's StatsJSON of a sample.
fn docker_cpu(s: &StatsRecord) -> Value {
    json!({
        "cpu_usage": {
            "total_usage": s.cpu_nano,
            "usage_in_kernelmode": s.cpu_system_nano,
            "usage_in_usermode": s.cpu_user_nano,
        },
        "system_cpu_usage": s.host_cpu_nano,
        "online_cpus": s.online_cpus,
        "throttling_data": {
            "periods": s.cpu_periods,
            "throttled_periods": s.cpu_throttled_periods,
            "throttled_time": s.cpu_throttled_nano,
        },
    })
}

/// The CPU use in % between two samples, as podman's (0 without the one
/// before).
fn cpu_between(s: &StatsRecord, pre: Option<&StatsRecord>) -> f64 {
    match pre {
        Some(pre) if pre.time_ns > 0 && s.time_ns > pre.time_ns => {
            s.cpu_nano.saturating_sub(pre.cpu_nano) as f64 / (s.time_ns - pre.time_ns) as f64
                * 100.0
        }
        _ => 0.0,
    }
}

/// Docker's StatsJSON of the sample `s`, `pre` the one before it (none: a
/// blank one, as podman's).
pub fn docker(s: &StatsRecord, pre: Option<&StatsRecord>, libpod: bool) -> Value {
    let io = if s.block_read > 0 || s.block_write > 0 {
        json!([
            {"major": 0, "minor": 0, "op": "read", "value": s.block_read},
            {"major": 0, "minor": 0, "op": "write", "value": s.block_write},
        ])
    } else {
        json!([])
    };
    let mut cpu = docker_cpu(s);
    cpu["cpu"] = json!(cpu_between(s, pre));
    let precpu = match pre {
        Some(pre) => {
            let mut p = docker_cpu(pre);
            p["cpu"] = json!(0);
            p
        }
        None => json!({
            "cpu_usage": {"total_usage": 0, "usage_in_kernelmode": 0, "usage_in_usermode": 0},
            "cpu": 0,
        }),
    };
    let networks: Map<String, Value> = s
        .networks
        .iter()
        .map(|n| {
            let counters = json!({
                "rx_bytes": n.rx_bytes, "rx_packets": n.rx_packets,
                "rx_errors": n.rx_errors, "rx_dropped": n.rx_dropped,
                "tx_bytes": n.tx_bytes, "tx_packets": n.tx_packets,
                "tx_errors": n.tx_errors, "tx_dropped": n.tx_dropped,
            });
            (n.name.clone(), counters)
        })
        .collect();
    json!({
        "read": rfc3339(s.time_ns),
        "preread": rfc3339(pre.map_or(0, |p| p.time_ns)),
        "pids_stats": {"current": s.pids},
        "blkio_stats": {"io_service_bytes_recursive": io, "io_serviced_recursive": []},
        "num_procs": 0,
        "storage_stats": {},
        "cpu_stats": cpu,
        "precpu_stats": precpu,
        // (the cgroup v2 names: Docker's client takes inactive_file off the
        // usage)
        "memory_stats": {
            "usage": s.mem_usage,
            "limit": s.mem_limit,
            "stats": {
                "anon": s.mem_anon,
                "file": s.mem_file,
                "inactive_file": s.mem_usage.saturating_sub(s.mem_working_set),
                "pgfault": s.page_faults,
                "pgmajfault": s.major_page_faults,
            },
        },
        "networks": networks,
        "name": format!("/{}", s.name),
        // (podman keeps its libpod route's `Id`)
        (if libpod { "Id" } else { "id" }): s.id,
    })
}

/// A size as go-units' HumanSize writes it: 4 significant digits, units
/// of 1000 (`12.18MB`).
pub fn human_size(n: u64) -> String {
    crate::units::go_size(n as f64)
}

/// go-units' BytesSize: units of 1024 (`11.62MiB`).
fn bytes_size(n: u64) -> String {
    crate::units::go_bytes_size(n as f64)
}

fn pair(a: u64, b: u64, f: fn(u64) -> String) -> String {
    if a == 0 && b == 0 {
        "-- / --".into()
    } else {
        format!("{} / {}", f(a), f(b))
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// podman's PodStatsReport of the containers of the pod `pod_id`, a row
/// each (the text of its columns).
pub fn pod_rows(pod_id: &str, stats: &[StatsRecord]) -> Vec<Value> {
    stats
        .iter()
        .map(|s| {
            json!({
                "CPU": format!("{:.2}%", s.cpu_percent),
                "MemUsage": pair(s.mem_usage, s.mem_limit, human_size),
                "MemUsageBytes": pair(s.mem_usage, s.mem_limit, bytes_size),
                "Mem": format!("{:.2}%", mem_percent(s)),
                "NetIO": pair(rx(s), tx(s), human_size),
                "BlockIO": pair(s.block_read, s.block_write, human_size),
                "PIDS": if s.pids > 0 { s.pids.to_string() } else { "--".into() },
                "Pod": short(pod_id),
                "CID": short(&s.id),
                "Name": s.name,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StatsRecord {
        StatsRecord {
            id: "0123456789abcdef".into(),
            name: "c1".into(),
            running: true,
            time_ns: 3_000_000_000,
            started_ns: 1_000_000_000,
            cpu_nano: 1_000_000_000,
            cpu_user_nano: 600_000_000,
            cpu_system_nano: 400_000_000,
            cpu_percent: 25.0,
            mem_usage: 400,
            mem_working_set: 300,
            mem_limit: 1000,
            block_read: 5,
            networks: vec![
                InterfaceStats {
                    name: "eth0".into(),
                    rx_bytes: 100,
                    tx_bytes: 200,
                    tx_dropped: 7,
                    ..Default::default()
                },
                InterfaceStats {
                    name: "eth1".into(),
                    rx_bytes: 1,
                    tx_bytes: 1,
                    ..Default::default()
                },
            ],
            pids: 3,
            ..Default::default()
        }
    }

    #[test]
    fn libpod_s_stats() {
        let v = libpod(&sample());
        assert_eq!(
            (v["CPU"].clone(), v["AvgCPU"].clone()),
            (json!(25.0), json!(50.0))
        );
        assert_eq!(
            (v["NetInput"].clone(), v["NetOutput"].clone()),
            (json!(101), json!(201))
        );
        assert_eq!(v["Network"]["eth0"]["RxBytes"], 100);
        assert_eq!(v["Network"]["eth0"]["TxDropped"], 7);
        assert_eq!(
            (v["MemPerc"].clone(), v["UpTime"].clone()),
            (json!(40.0), json!(2_000_000_000))
        );
        // (the size of what it wrote only when asked)
        assert!(v["RwBytes"].is_null());
        let report = libpod_report(&[sample(), StatsRecord::default()]);
        assert!(report["Error"].is_null());
        assert_eq!(report["Stats"][1]["Network"], Value::Null);
    }

    #[test]
    fn docker_s_stats_compare_two_samples() {
        let pre = StatsRecord {
            time_ns: 2_000_000_000,
            cpu_nano: 500_000_000,
            ..sample()
        };
        let v = docker(&sample(), Some(&pre), false);
        assert_eq!(v["cpu_stats"]["cpu"], 50.0);
        assert_eq!(
            v["cpu_stats"]["cpu_usage"]["usage_in_kernelmode"],
            400_000_000
        );
        assert_eq!(v["precpu_stats"]["cpu_usage"]["total_usage"], 500_000_000);
        assert_eq!(v["preread"], "1970-01-01T00:00:02Z");
        assert_eq!(v["memory_stats"]["stats"]["inactive_file"], 100);
        assert_eq!(v["networks"]["eth0"]["tx_bytes"], 200);
        assert_eq!(
            v["blkio_stats"]["io_service_bytes_recursive"][0]["value"],
            5
        );
        assert_eq!(
            (v["name"].clone(), v["pids_stats"]["current"].clone()),
            (json!("/c1"), json!(3))
        );
        let first = docker(&sample(), None, false);
        assert_eq!(first["cpu_stats"]["cpu"], 0.0);
        assert_eq!(first["precpu_stats"]["cpu_usage"]["total_usage"], 0);
        assert_eq!(first["preread"], "0001-01-01T00:00:00Z");
        let (compat, libpod) = (
            docker(&sample(), None, false),
            docker(&sample(), None, true),
        );
        assert_eq!(
            (&compat["id"], &compat["Id"]),
            (&json!("0123456789abcdef"), &Value::Null)
        );
        assert_eq!(
            (&libpod["Id"], &libpod["id"]),
            (&json!("0123456789abcdef"), &Value::Null)
        );
    }

    #[test]
    fn the_rows_of_a_pod_are_podman_s_text() {
        assert_eq!(human_size(12_180_391), "12.18MB");
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(999), "999B");
        assert_eq!(bytes_size(12_180_391), "11.62MiB");
        assert_eq!(bytes_size(1024), "1KiB");
        let rows = pod_rows("feedfacecafebeef", &[sample(), StatsRecord::default()]);
        assert_eq!(rows[0]["Pod"], "feedfacecafe");
        assert_eq!(rows[0]["CID"], "0123456789ab");
        assert_eq!(rows[0]["CPU"], "25.00%");
        assert_eq!(rows[0]["MemUsage"], "400B / 1kB");
        assert_eq!(rows[0]["NetIO"], "101B / 201B");
        assert_eq!(rows[0]["PIDS"], "3");
        assert_eq!(rows[1]["MemUsage"], "-- / --");
        assert_eq!(rows[1]["PIDS"], "--");
    }
}
