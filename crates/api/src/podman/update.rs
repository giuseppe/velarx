// SPDX-License-Identifier: Apache-2.0
//! The update of a container: the documents of libpod's and Docker's routes
//! as the engine's [`UpdateSpec`].  What velarx has no support for is refused
//! here, naming it; what the values mean is the engine's.

use super::call::refuse_field;
use super::error::{ApiError, ApiResult};
use serde::Deserialize;
use serde_json::Value;
use velarx_limit_core::{limit_of, nano_cpus_max, CpuMax, Limit, MAX_QUOTA, MIN_QUOTA};
use velarx_proto::engine::{PodmanHealthUpdate, UpdateBlockIo, UpdateDevice, UpdateSpec};
use velarx_proto::pod::RestartPolicy;
use velarx_proto::request::{parse_device_rule, DeviceRule, Ulimit};

/// The members of a libpod update that are the OCI resources.
#[derive(Deserialize, Default)]
#[serde(default)]
struct LibpodMemory {
    limit: Option<i64>,
    reservation: Option<i64>,
    swap: Option<i64>,
    swappiness: Option<i64>,
    kernel: Value,
    #[serde(rename = "kernelTCP")]
    kernel_tcp: Value,
    #[serde(rename = "useHierarchy")]
    use_hierarchy: Value,
    #[serde(rename = "checkBeforeUpdate")]
    check_before_update: Value,
    #[serde(rename = "disableOOMKiller")]
    disable_oom_killer: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LibpodCpu {
    quota: Option<i64>,
    period: Option<u64>,
    shares: Option<u64>,
    cpus: Option<String>,
    mems: Option<String>,
    #[serde(rename = "realtimeRuntime")]
    realtime_runtime: Option<i64>,
    #[serde(rename = "realtimePeriod")]
    realtime_period: Option<u64>,
    burst: Value,
    idle: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Pids {
    limit: Option<i64>,
}

/// An OCI device of `blockIO`: by numbers, with a weight or a rate.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct OciDevice {
    major: Option<u64>,
    minor: Option<u64>,
    weight: Option<u64>,
    #[serde(rename = "leafWeight")]
    leaf_weight: Value,
    rate: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct OciBlockIo {
    weight: Option<u64>,
    #[serde(rename = "leafWeight")]
    leaf_weight: Value,
    #[serde(rename = "weightDevice")]
    weight_device: Vec<OciDevice>,
    #[serde(rename = "throttleReadBpsDevice")]
    read_bps: Vec<OciDevice>,
    #[serde(rename = "throttleWriteBpsDevice")]
    write_bps: Vec<OciDevice>,
    #[serde(rename = "throttleReadIOPSDevice")]
    read_iops: Vec<OciDevice>,
    #[serde(rename = "throttleWriteIOPSDevice")]
    write_iops: Vec<OciDevice>,
}

/// An OCI device cgroup rule.
#[derive(Deserialize, Default)]
#[serde(default)]
struct OciRule {
    allow: bool,
    #[serde(rename = "type")]
    kind: Option<String>,
    major: Option<i64>,
    minor: Option<i64>,
    access: Option<String>,
}

/// A device of podman's `DeviceReadBPs` and the like: a path with a weight
/// or a rate.
#[derive(Deserialize, Default)]
#[serde(default)]
struct PathValue {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Weight")]
    weight: i64,
    #[serde(rename = "Rate")]
    rate: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LibpodRlimit {
    #[serde(rename = "type")]
    kind: String,
    soft: u64,
    hard: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Libpod {
    memory: LibpodMemory,
    cpu: LibpodCpu,
    pids: Pids,
    #[serde(rename = "hugepageLimits")]
    hugepage_limits: Value,
    network: Value,
    rdma: Value,
    unified: Value,
    #[serde(rename = "blockIO")]
    block_io: OciBlockIo,
    devices: Vec<OciRule>,
    #[serde(rename = "BlkIOWeightDevice")]
    weight_devices: Vec<PathValue>,
    #[serde(rename = "DeviceReadBPs")]
    read_bps: Vec<PathValue>,
    #[serde(rename = "DeviceWriteBPs")]
    write_bps: Vec<PathValue>,
    #[serde(rename = "DeviceReadIOPs")]
    read_iops: Vec<PathValue>,
    #[serde(rename = "DeviceWriteIOPs")]
    write_iops: Vec<PathValue>,
    #[serde(rename = "Env")]
    env: Vec<String>,
    #[serde(rename = "UnsetEnv")]
    unset_env: Vec<String>,
    r_limits: Option<Vec<LibpodRlimit>>,
}

/// The document without the members that are null: Go's clients send `null`
/// for a list or an object they do not use, which is what is absent.
fn without_nulls(v: Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, without_nulls(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(without_nulls).collect()),
        v => v,
    }
}

fn refuse(scope: &str, members: &[(&str, &Value)]) -> ApiResult<()> {
    for (name, value) in members {
        let at = if scope.is_empty() {
            name.to_string()
        } else {
            format!("{scope}.{name}")
        };
        refuse_field(&at, value)?;
    }
    Ok(())
}

fn oci_devices(list: Vec<OciDevice>, weights: bool) -> ApiResult<Vec<UpdateDevice>> {
    list.into_iter()
        .map(|d| {
            let (Some(major), Some(minor)) = (d.major, d.minor) else {
                return Err(ApiError::bad_request("a device has no major or minor"));
            };
            refuse_field("blockIO.weightDevice.leafWeight", &d.leaf_weight)?;
            // (a weight where a rate goes, or the other way round)
            let (value, other, other_name) = if weights {
                (d.weight, d.rate.is_some(), "rate")
            } else {
                (d.rate, d.weight.is_some(), "weight")
            };
            if other {
                return Err(ApiError::bad_request(format!(
                    "invalid `{other_name}` of a block IO device"
                )));
            }
            Ok(UpdateDevice {
                major: Some(major),
                minor: Some(minor),
                value: value.ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "invalid `{}` of a block IO device",
                        if weights { "weight" } else { "rate" }
                    ))
                })?,
                ..Default::default()
            })
        })
        .collect()
}

fn path_devices(list: Vec<PathValue>, weights: bool) -> Vec<UpdateDevice> {
    list.into_iter()
        .map(|d| UpdateDevice {
            path: Some(d.path),
            value: if weights { d.weight } else { d.rate }.max(0) as u64,
            ..Default::default()
        })
        .collect()
}

fn rule_of(r: OciRule) -> ApiResult<DeviceRule> {
    // (a deny would replace what the container was given)
    if !r.allow {
        return Err(ApiError::not_implemented(
            "deny rules of devices are not supported",
        ));
    }
    Ok(DeviceRule {
        typ: r.kind.unwrap_or_else(|| "a".into()),
        major: r.major,
        minor: r.minor,
        access: r.access.unwrap_or_else(|| "rwm".into()),
    })
}

/// libpod's update: the OCI resources, the environment, the devices'
/// limits, the rlimits, the health check, and the restart policy of the
/// query.
pub(super) fn libpod(body: Option<Value>, restart: Option<RestartPolicy>) -> ApiResult<UpdateSpec> {
    let body = without_nulls(body.unwrap_or(Value::Null));
    let decode = |e: serde_json::Error| ApiError::bad_request(format!("decode the update: {e}"));
    let (l, health): (Libpod, PodmanHealthUpdate) = if body.is_null() {
        Default::default()
    } else {
        (
            serde_json::from_value(body.clone()).map_err(decode)?,
            serde_json::from_value(body).map_err(decode)?,
        )
    };
    // cgroup v2 has neither: the runtime's words
    for (member, set, why) in [
        (
            "cpu.realtimeRuntime",
            l.cpu.realtime_runtime.is_some_and(|v| v != 0),
            "realtime runtime not supported on cgroupv2",
        ),
        (
            "cpu.realtimePeriod",
            l.cpu.realtime_period.is_some_and(|v| v != 0),
            "realtime period not supported on cgroupv2",
        ),
        (
            "memory.swappiness",
            l.memory.swappiness.is_some_and(|v| v >= 0),
            "cannot set memory swappiness with cgroupv2",
        ),
    ] {
        if set {
            return Err(ApiError::bad_request(format!("{why} ({member})")));
        }
    }
    refuse(
        "memory",
        &[
            ("kernel", &l.memory.kernel),
            ("kernelTCP", &l.memory.kernel_tcp),
            ("useHierarchy", &l.memory.use_hierarchy),
            ("checkBeforeUpdate", &l.memory.check_before_update),
            ("disableOOMKiller", &l.memory.disable_oom_killer),
        ],
    )?;
    refuse("cpu", &[("burst", &l.cpu.burst), ("idle", &l.cpu.idle)])?;
    refuse(
        "",
        &[
            ("hugepageLimits", &l.hugepage_limits),
            ("network", &l.network),
            ("rdma", &l.rdma),
            ("unified", &l.unified),
        ],
    )?;
    refuse_field("blockIO.leafWeight", &l.block_io.leaf_weight)?;
    let mut block_io = UpdateBlockIo {
        weight: l.block_io.weight,
        weight_devices: oci_devices(l.block_io.weight_device, true)?,
        read_bps: oci_devices(l.block_io.read_bps, false)?,
        write_bps: oci_devices(l.block_io.write_bps, false)?,
        read_iops: oci_devices(l.block_io.read_iops, false)?,
        write_iops: oci_devices(l.block_io.write_iops, false)?,
    };
    block_io
        .weight_devices
        .extend(path_devices(l.weight_devices, true));
    block_io.read_bps.extend(path_devices(l.read_bps, false));
    block_io.write_bps.extend(path_devices(l.write_bps, false));
    block_io.read_iops.extend(path_devices(l.read_iops, false));
    block_io
        .write_iops
        .extend(path_devices(l.write_iops, false));
    Ok(UpdateSpec {
        memory: l
            .memory
            .limit
            .map(|v| byte_limit("Memory", v))
            .transpose()?,
        memory_reservation: l
            .memory
            .reservation
            .map(|v| byte_limit("MemoryReservation", v))
            .transpose()?,
        memory_swap: l
            .memory
            .swap
            .map(|v| byte_limit("MemorySwap", v))
            .transpose()?,
        cpu_quota: l.cpu.quota,
        cpu_period: l.cpu.period,
        cpu_shares: l.cpu.shares,
        cpuset_cpus: l.cpu.cpus,
        cpuset_mems: l.cpu.mems,
        pids_limit: l.pids.limit,
        block_io,
        device_rules: l
            .devices
            .into_iter()
            .map(rule_of)
            .collect::<ApiResult<_>>()?,
        env: l.env,
        unset_env: l.unset_env,
        restart,
        ulimits: l.r_limits.map(|list| {
            list.into_iter()
                .map(|r| Ulimit {
                    name: r.kind,
                    soft: r.soft,
                    hard: r.hard,
                })
                .collect()
        }),
        health: health.spec().map_err(ApiError::internal)?,
    })
}

/// Docker's limit: a negative one is none.
fn limit(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A byte limit of an update: 0 is none, -1 is no limit (both go on to the
/// engine), another number below 1 is refused.
fn byte_limit(name: &str, v: i64) -> ApiResult<i64> {
    match limit_of(v) {
        Limit::Invalid => Err(ApiError::bad_request(format!(
            "invalid {name} {v}: bytes, 0 or -1"
        ))),
        _ => Ok(v),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerUlimit {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Soft")]
    soft: i64,
    #[serde(rename = "Hard")]
    hard: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerRestart {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "MaximumRetryCount")]
    maximum_retry_count: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Docker {
    #[serde(rename = "Memory")]
    memory: i64,
    #[serde(rename = "MemoryReservation")]
    memory_reservation: i64,
    #[serde(rename = "MemorySwap")]
    memory_swap: i64,
    #[serde(rename = "NanoCpus")]
    nano_cpus: i64,
    #[serde(rename = "CpuQuota")]
    cpu_quota: i64,
    #[serde(rename = "CpuPeriod")]
    cpu_period: i64,
    #[serde(rename = "CpuShares")]
    cpu_shares: i64,
    #[serde(rename = "CpusetCpus")]
    cpuset_cpus: String,
    #[serde(rename = "CpusetMems")]
    cpuset_mems: String,
    #[serde(rename = "PidsLimit")]
    pids_limit: Option<i64>,
    #[serde(rename = "BlkioWeight")]
    blkio_weight: i64,
    #[serde(rename = "BlkioWeightDevice")]
    weight_devices: Vec<PathValue>,
    #[serde(rename = "BlkioDeviceReadBps")]
    read_bps: Vec<PathValue>,
    #[serde(rename = "BlkioDeviceWriteBps")]
    write_bps: Vec<PathValue>,
    #[serde(rename = "BlkioDeviceReadIOps")]
    read_iops: Vec<PathValue>,
    #[serde(rename = "BlkioDeviceWriteIOps")]
    write_iops: Vec<PathValue>,
    #[serde(rename = "DeviceCgroupRules")]
    device_cgroup_rules: Vec<String>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: DockerRestart,
    #[serde(rename = "Ulimits")]
    ulimits: Vec<DockerUlimit>,
    #[serde(rename = "CpuRealtimeRuntime")]
    cpu_realtime_runtime: i64,
    #[serde(rename = "CpuRealtimePeriod")]
    cpu_realtime_period: i64,
    #[serde(rename = "MemorySwappiness")]
    memory_swappiness: Option<i64>,
    #[serde(rename = "CpuCount")]
    cpu_count: Value,
    #[serde(rename = "CpuPercent")]
    cpu_percent: Value,
    #[serde(rename = "IOMaximumBandwidth")]
    io_maximum_bandwidth: Value,
    #[serde(rename = "IOMaximumIOps")]
    io_maximum_iops: Value,
    #[serde(rename = "KernelMemory")]
    kernel_memory: Value,
    #[serde(rename = "KernelMemoryTCP")]
    kernel_memory_tcp: Value,
    #[serde(rename = "OomKillDisable")]
    oom_kill_disable: Value,
    #[serde(rename = "CgroupParent")]
    cgroup_parent: Value,
    #[serde(rename = "Devices")]
    devices: Value,
    #[serde(rename = "DeviceRequests")]
    device_requests: Value,
}

/// Docker's update: `Resources` and the restart policy.
pub(super) fn docker(body: Option<Value>) -> ApiResult<UpdateSpec> {
    let d: Docker = match body.map(without_nulls) {
        Some(v) if !v.is_null() => serde_json::from_value(v)
            .map_err(|e| ApiError::bad_request(format!("decode the update: {e}")))?,
        _ => Docker::default(),
    };
    refuse(
        "",
        &[
            ("CpuCount", &d.cpu_count),
            ("CpuPercent", &d.cpu_percent),
            ("IOMaximumBandwidth", &d.io_maximum_bandwidth),
            ("IOMaximumIOps", &d.io_maximum_iops),
            ("KernelMemory", &d.kernel_memory),
            ("KernelMemoryTCP", &d.kernel_memory_tcp),
            ("OomKillDisable", &d.oom_kill_disable),
            ("CgroupParent", &d.cgroup_parent),
            ("Devices", &d.devices),
            ("DeviceRequests", &d.device_requests),
        ],
    )?;
    // cgroup v2 has none of these: the runtime's words
    for (member, set, why) in [
        (
            "CpuRealtimeRuntime",
            d.cpu_realtime_runtime != 0,
            "realtime runtime not supported on cgroupv2",
        ),
        (
            "CpuRealtimePeriod",
            d.cpu_realtime_period != 0,
            "realtime period not supported on cgroupv2",
        ),
        (
            "MemorySwappiness",
            d.memory_swappiness.is_some_and(|v| v >= 0),
            "cannot set memory swappiness with cgroupv2",
        ),
    ] {
        if set {
            return Err(ApiError::bad_request(format!("{why} ({member})")));
        }
    }
    let given = |v: i64| (v != 0).then_some(v);
    let (cpu_quota, cpu_period) = if d.nano_cpus > 0 {
        match nano_cpus_max(d.nano_cpus) {
            CpuMax::Quota { quota, period } => (Some(quota as i64), Some(period)),
            _ => {
                return Err(ApiError::bad_request(format!(
                "invalid NanoCpus {}: a quota of {MIN_QUOTA} to {MAX_QUOTA} microseconds of 100000",
                d.nano_cpus
            )))
            }
        }
    } else if d.cpu_quota > 0 {
        (
            Some(d.cpu_quota),
            given(d.cpu_period).map(|v| v.max(0) as u64),
        )
    } else {
        (None, None)
    };
    let rules = d
        .device_cgroup_rules
        .iter()
        .map(|r| parse_device_rule(r).map_err(ApiError::bad_request))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(UpdateSpec {
        memory: given(d.memory)
            .map(|v| byte_limit("Memory", v))
            .transpose()?,
        memory_reservation: given(d.memory_reservation)
            .map(|v| byte_limit("MemoryReservation", v))
            .transpose()?,
        memory_swap: given(d.memory_swap)
            .map(|v| byte_limit("MemorySwap", v))
            .transpose()?,
        cpu_quota,
        cpu_period,
        cpu_shares: given(d.cpu_shares)
            .map(|v| {
                u64::try_from(v)
                    .map_err(|_| ApiError::bad_request(format!("CpuShares {v} is negative")))
            })
            .transpose()?,
        cpuset_cpus: Some(d.cpuset_cpus).filter(|s| !s.is_empty()),
        cpuset_mems: Some(d.cpuset_mems).filter(|s| !s.is_empty()),
        pids_limit: d.pids_limit.filter(|v| *v != 0),
        block_io: UpdateBlockIo {
            weight: (d.blkio_weight > 0).then_some(d.blkio_weight as u64),
            weight_devices: path_devices(d.weight_devices, true),
            read_bps: path_devices(d.read_bps, false),
            write_bps: path_devices(d.write_bps, false),
            read_iops: path_devices(d.read_iops, false),
            write_iops: path_devices(d.write_iops, false),
        },
        device_rules: rules,
        restart: (!d.restart_policy.name.is_empty()).then(|| RestartPolicy {
            name: d.restart_policy.name,
            maximum_retry_count: d.restart_policy.maximum_retry_count.max(0) as u32,
        }),
        ulimits: (!d.ulimits.is_empty()).then(|| {
            d.ulimits
                .into_iter()
                .map(|u| Ulimit {
                    name: u.name,
                    soft: limit(u.soft),
                    hard: limit(u.hard),
                })
                .collect()
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// What velarx has no support for is refused naming it, with the status
    /// the update always answered.
    #[test]
    fn what_an_update_cannot_do_is_refused() {
        for (is_libpod, body, name) in [
            (true, json!({"memory": {"kernel": 1}}), "memory.kernel"),
            (
                true,
                json!({"memory": {"kernelTCP": 1}}),
                "memory.kernelTCP",
            ),
            (
                true,
                json!({"memory": {"useHierarchy": true}}),
                "memory.useHierarchy",
            ),
            (
                true,
                json!({"memory": {"checkBeforeUpdate": true}}),
                "memory.checkBeforeUpdate",
            ),
            (
                true,
                json!({"memory": {"disableOOMKiller": true}}),
                "memory.disableOOMKiller",
            ),
            (true, json!({"cpu": {"burst": 5}}), "cpu.burst"),
            (true, json!({"cpu": {"idle": 1}}), "cpu.idle"),
            (
                true,
                json!({"hugepageLimits": [{"pageSize": "2MB", "limit": 1}]}),
                "hugepageLimits",
            ),
            (true, json!({"network": {"classID": 1}}), "network"),
            (true, json!({"rdma": {"mlx": {"hcaHandles": 1}}}), "rdma"),
            (true, json!({"unified": {"cpu.weight": "5"}}), "unified"),
            (
                true,
                json!({"devices": [{"allow": false, "access": "rwm"}]}),
                "deny rules",
            ),
            (false, json!({"CpuCount": 2}), "CpuCount"),
            (false, json!({"CpuPercent": 50}), "CpuPercent"),
            (false, json!({"IOMaximumIOps": 5}), "IOMaximumIOps"),
            (
                false,
                json!({"IOMaximumBandwidth": 5}),
                "IOMaximumBandwidth",
            ),
            (false, json!({"KernelMemory": 5}), "KernelMemory"),
            (false, json!({"KernelMemoryTCP": 5}), "KernelMemoryTCP"),
            (false, json!({"OomKillDisable": true}), "OomKillDisable"),
            (false, json!({"CgroupParent": "x"}), "CgroupParent"),
            (
                false,
                json!({"Devices": [{"PathOnHost": "/dev/null"}]}),
                "Devices",
            ),
            (
                false,
                json!({"DeviceRequests": [{"Driver": "cdi"}]}),
                "DeviceRequests",
            ),
        ] {
            let e = if is_libpod {
                libpod(Some(body.clone()), None)
            } else {
                docker(Some(body.clone()))
            }
            .err()
            .unwrap_or_else(|| panic!("{body}"));
            assert_eq!(e.status.as_u16(), 501, "{body}");
            assert!(e.message.contains(name), "{}", e.message);
        }
        // the runtime's words for what cgroup v2 does not have
        for body in [
            json!({"CpuRealtimeRuntime": 1}),
            json!({"CpuRealtimePeriod": 1}),
            json!({"MemorySwappiness": 10}),
        ] {
            let e = docker(Some(body)).err().unwrap();
            assert!(e.message.contains("cgroupv2"), "{}", e.message);
        }
        // the zero values a client sends
        docker(Some(
            json!({"CpuCount": 0, "KernelMemory": 0, "OomKillDisable": null,
                           "Devices": [], "MemorySwappiness": null}),
        ))
        .unwrap();
        libpod(
            Some(json!({"memory": {"kernel": 0}, "cpu": {"idle": 0}, "unified": {}})),
            None,
        )
        .unwrap();
        // the nulls a Go client sends for what it does not use
        let spec = libpod(
            Some(
                json!({"memory": null, "DeviceReadBPs": null, "blockIO": {"weightDevice": null},
                        "devices": null, "r_limits": null, "Env": null}),
            ),
            None,
        )
        .unwrap();
        assert_eq!(spec, UpdateSpec::default());
        docker(Some(
            json!({"Ulimits": null, "RestartPolicy": null, "BlkioWeightDevice": null}),
        ))
        .unwrap();
    }

    /// A count of CPUs that rounds to a quota of 0 would be no limit, and
    /// a negative count of shares would be a huge one.
    #[test]
    fn a_cpu_limit_is_never_turned_into_no_limit() {
        let quota = |nano: i64| docker(Some(json!({"NanoCpus": nano}))).map(|s| s.cpu_quota);
        assert_eq!(quota(1_500_000_000).unwrap(), Some(150_000));
        assert_eq!(quota(10_000_000).unwrap(), Some(1_000));
        for nano in [1, 9_999, 9_999_999, i64::MAX] {
            let e = quota(nano).unwrap_err();
            assert!(e.message.contains("NanoCpus"), "{nano}: {}", e.message);
        }
        assert_eq!(quota(0).unwrap(), None);
        assert_eq!(
            docker(Some(json!({"CpuShares": 512}))).unwrap().cpu_shares,
            Some(512)
        );
        let e = docker(Some(json!({"CpuShares": -1}))).unwrap_err();
        assert!(e.message.contains("negative"), "{}", e.message);
    }

    /// A memory below -1 is refused, not sent on to the runtime.
    #[test]
    fn a_negative_memory_is_refused() {
        for (docker_key, libpod_key) in [
            ("Memory", "limit"),
            ("MemorySwap", "swap"),
            ("MemoryReservation", "reservation"),
        ] {
            for v in [-2, i64::MIN] {
                let e = docker(Some(json!({ docker_key: v }))).unwrap_err();
                assert!(e.message.contains(docker_key), "{}", e.message);
                libpod(Some(json!({"memory": { libpod_key: v }})), None).unwrap_err();
            }
            for v in [-1, 100] {
                docker(Some(json!({ docker_key: v }))).unwrap();
                libpod(Some(json!({"memory": { libpod_key: v }})), None).unwrap();
            }
        }
    }

    #[test]
    fn the_ulimits_of_a_docker_update_and_the_r_limits_of_libpod_s() {
        let spec = docker(Some(json!({"Ulimits": [
            {"Name": "nofile", "Soft": 1024, "Hard": 2048},
            {"Name": "core", "Soft": -1, "Hard": -1},
        ]})))
        .unwrap();
        let list = spec.ulimits.unwrap();
        assert_eq!(
            list.iter()
                .map(|u| (u.name.as_str(), u.soft, u.hard))
                .collect::<Vec<_>>(),
            [("nofile", 1024, 2048), ("core", u64::MAX, u64::MAX)]
        );
        assert!(docker(Some(json!({"Ulimits": []})))
            .unwrap()
            .ulimits
            .is_none());
        // libpod's are its `r_limits`; an empty list is the host's
        assert!(libpod(Some(json!({"Ulimits": [{"Name": "nofile"}]})), None)
            .unwrap()
            .ulimits
            .is_none());
        assert_eq!(
            libpod(Some(json!({"r_limits": []})), None).unwrap().ulimits,
            Some(vec![])
        );
    }

    /// The health members become the times in nanoseconds, `disable` zero;
    /// none of them is no change.
    #[test]
    fn the_health_members_of_a_libpod_update() {
        assert!(libpod(Some(json!({"memory": {}})), None)
            .unwrap()
            .health
            .is_none());
        let h = libpod(
            Some(json!({"health_cmd": "echo hi", "health_interval": "10s",
                        "health_timeout": "disable", "health_retries": 7,
                        "health_startup_success": 2, "no_healthcheck": false})),
            None,
        )
        .unwrap()
        .health
        .unwrap();
        assert_eq!(
            (
                h.cmd.as_deref(),
                h.interval,
                h.timeout,
                h.retries,
                h.startup_success
            ),
            (
                Some("echo hi"),
                Some(10_000_000_000),
                Some(0),
                Some(7),
                Some(2)
            )
        );
        let e = libpod(Some(json!({"health_interval": "ten"})), None)
            .err()
            .unwrap();
        assert_eq!(e.status.as_u16(), 500);
        assert!(
            e.message.contains("time: invalid duration"),
            "{}",
            e.message
        );
    }

    #[test]
    fn the_devices_of_an_update_are_named_by_path_or_by_numbers() {
        let spec = libpod(
            Some(json!({
                "blockIO": {"weight": 300,
                            "weightDevice": [{"major": 8, "minor": 0, "weight": 100}],
                            "throttleReadBpsDevice": [{"major": 8, "minor": 1, "rate": 5}]},
                "DeviceWriteIOPs": [{"Path": "/dev/sda", "Rate": 1000}],
            })),
            None,
        )
        .unwrap();
        assert_eq!(spec.block_io.weight, Some(300));
        assert_eq!(
            spec.block_io.weight_devices,
            [UpdateDevice {
                major: Some(8),
                minor: Some(0),
                value: 100,
                ..Default::default()
            }]
        );
        assert_eq!(spec.block_io.read_bps[0].minor, Some(1));
        assert_eq!(
            spec.block_io.write_iops,
            [UpdateDevice {
                path: Some("/dev/sda".into()),
                value: 1000,
                ..Default::default()
            }]
        );
        // an unknown member of `blockIO` or of a device is refused, and a
        // weight where a rate goes
        assert!(libpod(Some(json!({"blockIO": {"nosuch": 1}})), None).is_err());
        for bad in [
            json!({"throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1, "nosuch": 1}]}),
            json!({"throttleReadBpsDevice": [{"major": 8, "minor": 0, "weight": 100}]}),
            json!({"throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1, "weight": 100}]}),
            json!({"weightDevice": [{"major": 8, "minor": 0, "weight": 100, "rate": 1}]}),
            json!({"throttleReadBpsDevice": [{"major": 8, "rate": 1}]}),
        ] {
            let e = libpod(Some(json!({ "blockIO": bad })), None).err().unwrap();
            assert_eq!(e.status.as_u16(), 400, "{bad}");
        }
        let e = libpod(Some(json!({"blockIO": {"leafWeight": 5}})), None)
            .err()
            .unwrap();
        assert_eq!(e.status.as_u16(), 501);
    }
}
