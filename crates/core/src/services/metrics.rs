// SPDX-License-Identifier: Apache-2.0
//! The metrics of containers and pods in the names of cAdvisor (what a
//! kubelet exports on `/metrics/cadvisor`): the descriptors, and the samples
//! read from the cgroup and the namespaces of the running containers.  A
//! sample has the values of the labels of its descriptor, in the same order.
//!
//! The values come from the cgroup of the container (cgroup v2), `/proc` and
//! the file system of its writable layer; a file the kernel does not have
//! (no `memory.peak`, no pressure information) gives the value 0 or no sample.

use super::cgroup::CgroupStats;
use std::fs;
use std::path::Path;
use velarx_wire::wire::{Descriptor, Sample};

/// The labels of every metric of a container.
const BASE: [&str; 3] = ["id", "image", "name"];

/// (name, help, counter, more labels)
type Row = (&'static str, &'static str, bool, &'static [&'static str]);

const DEVICE: &[&str] = &["device"];
const INTERFACE: &[&str] = &["interface"];
const NONE: &[&str] = &[];

const TABLE: &[Row] = &[
    ("container_blkio_device_usage_total", "Blkio Device bytes usage", true, &["device", "major", "minor", "operation"]),
    ("container_cpu_cfs_periods_total", "Number of elapsed enforcement period intervals.", true, NONE),
    ("container_cpu_cfs_throttled_periods_total", "Number of throttled period intervals.", true, NONE),
    ("container_cpu_cfs_throttled_seconds_total", "Total time duration the container has been throttled.", true, NONE),
    ("container_cpu_system_seconds_total", "Cumulative system cpu time consumed in seconds.", true, NONE),
    ("container_cpu_usage_seconds_total", "Cumulative cpu time consumed in seconds.", true, NONE),
    ("container_cpu_user_seconds_total", "Cumulative user cpu time consumed in seconds.", true, NONE),
    ("container_file_descriptors", "Number of open file descriptors for the container.", false, NONE),
    ("container_fs_inodes_free", "Number of available Inodes", false, DEVICE),
    ("container_fs_inodes_total", "Number of Inodes", false, DEVICE),
    ("container_fs_limit_bytes", "Number of bytes that can be consumed by the container on this filesystem.", false, DEVICE),
    ("container_fs_reads_bytes_total", "Cumulative count of bytes read", true, DEVICE),
    ("container_fs_reads_total", "Cumulative count of reads completed", true, DEVICE),
    ("container_fs_usage_bytes", "Number of bytes that are consumed by the container on this filesystem.", false, DEVICE),
    ("container_fs_writes_bytes_total", "Cumulative count of bytes written", true, DEVICE),
    ("container_fs_writes_total", "Cumulative count of writes completed", true, DEVICE),
    ("container_last_seen", "Last time a container was seen by the exporter", false, NONE),
    ("container_memory_cache", "Number of bytes of page cache memory.", false, NONE),
    ("container_memory_failcnt", "Number of memory usage hits limits", true, NONE),
    ("container_memory_failures_total", "Cumulative count of memory allocation failures.", true, &["failure_type", "scope"]),
    ("container_memory_kernel_usage", "Size of kernel memory allocated in bytes.", false, NONE),
    ("container_memory_mapped_file", "Size of memory mapped files in bytes.", false, NONE),
    ("container_memory_max_usage_bytes", "Maximum memory usage recorded in bytes", false, NONE),
    ("container_memory_rss", "Size of RSS in bytes.", false, NONE),
    ("container_memory_swap", "Container swap usage in bytes.", false, NONE),
    ("container_memory_usage_bytes", "Current memory usage in bytes, including all memory regardless of when it was accessed", false, NONE),
    ("container_memory_working_set_bytes", "Current working set in bytes.", false, NONE),
    ("container_network_receive_bytes_total", "Cumulative count of bytes received", true, INTERFACE),
    ("container_network_receive_errors_total", "Cumulative count of errors encountered while receiving", true, INTERFACE),
    ("container_network_receive_packets_dropped_total", "Cumulative count of packets dropped while receiving", true, INTERFACE),
    ("container_network_receive_packets_total", "Cumulative count of packets received", true, INTERFACE),
    ("container_network_transmit_bytes_total", "Cumulative count of bytes transmitted", true, INTERFACE),
    ("container_network_transmit_errors_total", "Cumulative count of errors encountered while transmitting", true, INTERFACE),
    ("container_network_transmit_packets_dropped_total", "Cumulative count of packets dropped while transmitting", true, INTERFACE),
    ("container_network_transmit_packets_total", "Cumulative count of packets transmitted", true, INTERFACE),
    ("container_oom_events_total", "Count of out of memory events observed for the container", true, NONE),
    ("container_pressure_cpu_stalled_seconds_total", "Total time duration no tasks in the container could make progress due to CPU congestion.", true, NONE),
    ("container_pressure_cpu_waiting_seconds_total", "Total time duration tasks in the container have waited due to CPU congestion.", true, NONE),
    ("container_pressure_io_stalled_seconds_total", "Total time duration no tasks in the container could make progress due to IO congestion.", true, NONE),
    ("container_pressure_io_waiting_seconds_total", "Total time duration tasks in the container have waited due to IO congestion.", true, NONE),
    ("container_pressure_memory_stalled_seconds_total", "Total time duration no tasks in the container could make progress due to memory congestion.", true, NONE),
    ("container_pressure_memory_waiting_seconds_total", "Total time duration tasks in the container have waited due to memory congestion.", true, NONE),
    ("container_processes", "Number of processes running inside the container.", false, NONE),
    ("container_sockets", "Number of open sockets for the container.", false, NONE),
    ("container_spec_cpu_period", "CPU period of the container.", false, NONE),
    ("container_spec_cpu_quota", "CPU quota of the container.", false, NONE),
    ("container_spec_cpu_shares", "CPU share of the container.", false, NONE),
    ("container_spec_memory_limit_bytes", "Memory limit for the container (0: none).", false, NONE),
    ("container_spec_memory_swap_limit_bytes", "Memory swap limit for the container (0: none).", false, NONE),
    ("container_start_time_seconds", "Start time of the container since unix epoch in seconds.", false, NONE),
    ("container_threads", "Number of threads running inside the container", false, NONE),
    ("container_threads_max", "Maximum number of threads allowed inside the container, infinity if value is zero", false, NONE),
];

/// The descriptors of every metric.
pub fn descriptors() -> Vec<Descriptor> {
    TABLE
        .iter()
        .map(|(name, help, counter, more)| Descriptor {
            name: name.to_string(),
            help: help.to_string(),
            counter: *counter,
            labels: BASE
                .iter()
                .chain(more.iter())
                .map(|l| l.to_string())
                .collect(),
        })
        .collect()
}

/// What a container is called in the labels of its samples.
pub struct Identity<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub image: &'a str,
}

impl Identity<'_> {
    fn sample(&self, name: &str, more: &[&str], value: f64) -> Sample {
        let mut labels = vec![
            self.id.to_string(),
            self.image.to_string(),
            self.name.to_string(),
        ];
        labels.extend(more.iter().map(|l| l.to_string()));
        Sample {
            name: name.to_string(),
            labels,
            value,
        }
    }
}

/// The file system the writable layer of a container is on.
pub struct Filesystem {
    pub device: String,
    pub limit_bytes: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
    /// What the container wrote
    pub used_bytes: u64,
}

/// The device number of the file system of PATH (`major:minor`) with its
/// size and inodes.
pub fn filesystem_of(path: &Path, used_bytes: u64) -> Option<Filesystem> {
    use std::os::unix::fs::MetadataExt;
    let dev = fs::metadata(path).ok()?.dev();
    let st = rustix::fs::statvfs(path).ok()?;
    Some(Filesystem {
        device: format!("{}:{}", libc::major(dev), libc::minor(dev)),
        limit_bytes: st.f_blocks.saturating_mul(st.f_frsize),
        inodes_total: st.f_files,
        inodes_free: st.f_ffree,
        used_bytes,
    })
}

/// "some"/"full" `total=` of a pressure file, in seconds.
fn pressure(dir: &Path, file: &str, kind: &str) -> Option<f64> {
    let text = fs::read_to_string(dir.join(file)).ok()?;
    text.lines()
        .find_map(|l| {
            l.strip_prefix(kind)?
                .split_whitespace()
                .find_map(|f| f.strip_prefix("total="))
        })
        .and_then(|v| v.parse::<f64>().ok())
        .map(|us| us / 1e6)
}

/// Per device: (major, minor, rbytes, wbytes, rios, wios) of `io.stat`.
fn io_devices(dir: &Path) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let Ok(text) = fs::read_to_string(dir.join("io.stat")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let (maj, min) = parts.next()?.split_once(':')?;
            let mut v = (maj.parse().ok()?, min.parse().ok()?, 0, 0, 0, 0);
            for p in parts {
                let n = |s: &str| s.parse::<u64>().unwrap_or(0);
                if let Some(x) = p.strip_prefix("rbytes=") {
                    v.2 = n(x);
                } else if let Some(x) = p.strip_prefix("wbytes=") {
                    v.3 = n(x);
                } else if let Some(x) = p.strip_prefix("rios=") {
                    v.4 = n(x);
                } else if let Some(x) = p.strip_prefix("wios=") {
                    v.5 = n(x);
                }
            }
            Some(v)
        })
        .collect()
}

/// The processes of the cgroup and, of them, the number of open descriptors
/// and of those that are sockets.
fn processes(dir: &Path) -> (u64, u64, u64) {
    let Ok(text) = fs::read_to_string(dir.join("cgroup.procs")) else {
        return (0, 0, 0);
    };
    let (mut procs, mut fds, mut sockets) = (0, 0, 0);
    for pid in text.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
        procs += 1;
        let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for e in rd.flatten() {
            fds += 1;
            if fs::read_link(e.path()).is_ok_and(|l| l.to_string_lossy().starts_with("socket:")) {
                sockets += 1;
            }
        }
    }
    (procs, fds, sockets)
}

/// The shares the weight of `cpu.weight` stands for (the inverse of what
/// the runtime writes for `cpu.shares`).
fn shares_of(weight: u64) -> u64 {
    2 + weight.saturating_sub(1) * 262_142 / 9_999
}

/// What the samples of a running container are made from.
pub struct Reading<'a> {
    pub who: Identity<'a>,
    pub stats: &'a CgroupStats,
    /// The cgroup of the container
    pub dir: &'a Path,
    pub started_ns: i64,
    pub now_ns: i64,
    pub filesystem: Option<Filesystem>,
}

/// The samples of a container.
pub fn container_samples(r: &Reading) -> Vec<Sample> {
    let (w, s) = (&r.who, r.stats);
    let secs = |us: u64| us as f64 / 1e6;
    let mut out = vec![
        w.sample("container_cpu_cfs_periods_total", &[], s.cpu_periods as f64),
        w.sample(
            "container_cpu_cfs_throttled_periods_total",
            &[],
            s.cpu_throttled_periods as f64,
        ),
        w.sample(
            "container_cpu_cfs_throttled_seconds_total",
            &[],
            secs(s.cpu_throttled_usec),
        ),
        w.sample(
            "container_cpu_system_seconds_total",
            &[],
            secs(s.cpu_system_usec),
        ),
        w.sample(
            "container_cpu_usage_seconds_total",
            &[],
            secs(s.cpu_usage_usec),
        ),
        w.sample(
            "container_cpu_user_seconds_total",
            &[],
            secs(s.cpu_user_usec),
        ),
        w.sample("container_last_seen", &[], r.now_ns as f64 / 1e9),
        w.sample("container_memory_cache", &[], s.memory_file as f64),
        w.sample("container_memory_failcnt", &[], s.memory_limit_hits as f64),
        w.sample("container_memory_kernel_usage", &[], s.memory_kernel as f64),
        w.sample(
            "container_memory_mapped_file",
            &[],
            s.memory_mapped_file as f64,
        ),
        w.sample(
            "container_memory_max_usage_bytes",
            &[],
            s.memory_peak as f64,
        ),
        w.sample("container_memory_rss", &[], s.memory_anon as f64),
        w.sample("container_memory_swap", &[], s.memory_swap_usage as f64),
        w.sample("container_memory_usage_bytes", &[], s.memory_usage as f64),
        w.sample(
            "container_memory_working_set_bytes",
            &[],
            s.memory_usage.saturating_sub(s.memory_inactive_file) as f64,
        ),
        w.sample("container_oom_events_total", &[], s.oom_kills as f64),
        w.sample(
            "container_spec_cpu_period",
            &[],
            s.cpu_period.unwrap_or(100_000) as f64,
        ),
        w.sample(
            "container_spec_cpu_quota",
            &[],
            s.cpu_quota.unwrap_or(0).max(0) as f64,
        ),
        w.sample(
            "container_spec_cpu_shares",
            &[],
            shares_of(s.cpu_weight.unwrap_or(100)) as f64,
        ),
        w.sample(
            "container_spec_memory_limit_bytes",
            &[],
            s.memory_limit.unwrap_or(0) as f64,
        ),
        w.sample(
            "container_spec_memory_swap_limit_bytes",
            &[],
            s.memory_swap_limit.unwrap_or(0) as f64,
        ),
        w.sample(
            "container_start_time_seconds",
            &[],
            r.started_ns as f64 / 1e9,
        ),
        w.sample(
            "container_threads_max",
            &[],
            s.pids_limit.unwrap_or(0) as f64,
        ),
    ];
    for (kind, scope, v) in [
        ("pgfault", "container", s.page_faults),
        ("pgmajfault", "container", s.major_page_faults),
        ("pgfault", "hierarchy", s.page_faults),
        ("pgmajfault", "hierarchy", s.major_page_faults),
    ] {
        out.push(w.sample("container_memory_failures_total", &[kind, scope], v as f64));
    }
    let threads = fs::read_to_string(r.dir.join("cgroup.threads"))
        .map(|t| t.lines().count() as u64)
        .unwrap_or(0);
    let (procs, fds, sockets) = processes(r.dir);
    out.push(w.sample("container_threads", &[], threads as f64));
    out.push(w.sample("container_processes", &[], procs as f64));
    out.push(w.sample("container_file_descriptors", &[], fds as f64));
    out.push(w.sample("container_sockets", &[], sockets as f64));
    for (name, file, kind) in [
        (
            "container_pressure_cpu_stalled_seconds_total",
            "cpu.pressure",
            "full",
        ),
        (
            "container_pressure_cpu_waiting_seconds_total",
            "cpu.pressure",
            "some",
        ),
        (
            "container_pressure_io_stalled_seconds_total",
            "io.pressure",
            "full",
        ),
        (
            "container_pressure_io_waiting_seconds_total",
            "io.pressure",
            "some",
        ),
        (
            "container_pressure_memory_stalled_seconds_total",
            "memory.pressure",
            "full",
        ),
        (
            "container_pressure_memory_waiting_seconds_total",
            "memory.pressure",
            "some",
        ),
    ] {
        if let Some(v) = pressure(r.dir, file, kind) {
            out.push(w.sample(name, &[], v));
        }
    }
    let devices = io_devices(r.dir);
    for (major, minor, rbytes, wbytes, _, _) in &devices {
        let device = format!("{major}:{minor}");
        for (op, v) in [("Read", rbytes), ("Write", wbytes)] {
            out.push(w.sample(
                "container_blkio_device_usage_total",
                &[&device, &major.to_string(), &minor.to_string(), op],
                *v as f64,
            ));
        }
    }
    if let Some(f) = &r.filesystem {
        out.push(w.sample(
            "container_fs_usage_bytes",
            &[&f.device],
            f.used_bytes as f64,
        ));
        out.push(w.sample(
            "container_fs_limit_bytes",
            &[&f.device],
            f.limit_bytes as f64,
        ));
        out.push(w.sample(
            "container_fs_inodes_total",
            &[&f.device],
            f.inodes_total as f64,
        ));
        out.push(w.sample(
            "container_fs_inodes_free",
            &[&f.device],
            f.inodes_free as f64,
        ));
        let (rb, wb, ri, wi) = devices.iter().fold((0, 0, 0, 0), |a, d| {
            (a.0 + d.2, a.1 + d.3, a.2 + d.4, a.3 + d.5)
        });
        out.push(w.sample("container_fs_reads_bytes_total", &[&f.device], rb as f64));
        out.push(w.sample("container_fs_writes_bytes_total", &[&f.device], wb as f64));
        out.push(w.sample("container_fs_reads_total", &[&f.device], ri as f64));
        out.push(w.sample("container_fs_writes_total", &[&f.device], wi as f64));
    }
    out
}

/// The samples of the interfaces of the network namespace in the text of
/// its `/proc/PID/net/dev`, but the loopback.
pub fn network_samples(who: &Identity, net_dev: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    for (name, c) in velarx_wire::wire::NetworkCounters::parse_net_dev(net_dev) {
        for (metric, value) in [
            ("container_network_receive_bytes_total", c.rx_bytes),
            ("container_network_receive_packets_total", c.rx_packets),
            ("container_network_receive_errors_total", c.rx_errors),
            (
                "container_network_receive_packets_dropped_total",
                c.rx_dropped,
            ),
            ("container_network_transmit_bytes_total", c.tx_bytes),
            ("container_network_transmit_packets_total", c.tx_packets),
            ("container_network_transmit_errors_total", c.tx_errors),
            (
                "container_network_transmit_packets_dropped_total",
                c.tx_dropped,
            ),
        ] {
            out.push(who.sample(metric, &[&name], value as f64));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An interface whose line does not have its 16 counters is left out,
    /// not exported with counters of zero.
    #[test]
    fn a_line_of_net_dev_that_cannot_be_read_is_left_out() {
        let who = Identity {
            id: "i",
            name: "n",
            image: "img",
        };
        let samples = network_samples(
            &who,
            "Inter-|   Receive\n face |bytes\n  eth0: 5 x 7 8 0 0 0 0 9 10 11 12 0 0 0 0\n  eth1: 5 6 7\n  eth2: 1 2 3 4 0 0 0 0 5 6 7 8 0 0 0 0\n",
        );
        assert_eq!(samples.len(), 8);
        assert!(samples.iter().all(|s| s.labels.last().unwrap() == "eth2"));
    }

    #[test]
    fn every_descriptor_has_a_help_and_the_base_labels() {
        let d = descriptors();
        assert!(d.len() > 50);
        for x in &d {
            assert!(!x.help.is_empty(), "{}", x.name);
            assert_eq!(&x.labels[..3], &["id", "image", "name"], "{}", x.name);
        }
        let names: std::collections::BTreeSet<_> = d.iter().map(|x| &x.name).collect();
        assert_eq!(names.len(), d.len(), "names are unique");
    }

    #[test]
    fn the_samples_have_the_labels_of_their_descriptors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cgroup.procs"), "").unwrap();
        fs::write(
            dir.path().join("io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("memory.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=2500000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n",
        )
        .unwrap();
        let stats = CgroupStats {
            memory_usage: 100,
            memory_inactive_file: 30,
            cpu_usage_usec: 1_500_000,
            ..CgroupStats::default()
        };
        let mut samples = container_samples(&Reading {
            who: Identity {
                id: "i",
                name: "n",
                image: "img",
            },
            stats: &stats,
            dir: dir.path(),
            started_ns: 2_000_000_000,
            now_ns: 3_000_000_000,
            filesystem: Some(Filesystem {
                device: "8:1".into(),
                limit_bytes: 1000,
                inodes_total: 10,
                inodes_free: 4,
                used_bytes: 7,
            }),
        });
        samples.extend(network_samples(
            &Identity { id: "i", name: "n", image: "img" },
            "Inter-|   Receive\n face |bytes\n    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n  eth0: 5 6 7 8 0 0 0 0 9 10 11 12 0 0 0 0\n",
        ));
        let d: std::collections::HashMap<_, _> = descriptors()
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        for s in &samples {
            assert_eq!(s.labels.len(), d[&s.name].labels.len(), "{}", s.name);
        }
        let value = |n: &str| samples.iter().find(|s| s.name == n).unwrap().value;
        assert_eq!(value("container_memory_working_set_bytes"), 70.0);
        assert_eq!(value("container_cpu_usage_seconds_total"), 1.5);
        assert_eq!(
            value("container_pressure_memory_waiting_seconds_total"),
            2.5
        );
        assert_eq!(
            value("container_pressure_memory_stalled_seconds_total"),
            1.0
        );
        assert_eq!(value("container_fs_usage_bytes"), 7.0);
        assert_eq!(value("container_fs_inodes_free"), 4.0);
        assert_eq!(value("container_fs_reads_bytes_total"), 10.0);
        assert_eq!(value("container_network_receive_bytes_total"), 5.0);
        assert_eq!(
            value("container_network_transmit_packets_dropped_total"),
            12.0
        );
        assert_eq!(value("container_start_time_seconds"), 2.0);
        assert!(!samples.iter().any(|s| s.labels.contains(&"lo".to_string())));
    }

    #[test]
    fn shares_follow_the_weight() {
        assert_eq!(shares_of(1), 2);
        assert_eq!(shares_of(10_000), 262_144);
        assert_eq!(shares_of(39), 998);
    }
}
