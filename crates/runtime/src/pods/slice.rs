// SPDX-License-Identifier: Apache-2.0
//! The cgroup of a pod whose containers are scopes of the systemd manager in
//! a slice (`--cgroup-parent=X.slice`, the cgroup driver `systemd` of the
//! kubelet): a slice of its own for the pod, `X-velarx_pod_<id>.slice`
//! below the parent, the unit the containers' scopes are made in.  Its
//! limits are the properties of the unit (`MemoryMax`, `CPUWeight`...), made
//! with it and changed by `SetUnitProperties`; the manager applies them to
//! the cgroup.  Like the scopes of the containers, the slice is a transient
//! unit of the manager of the user, or of the system for root, asked over its
//! private socket; the engine writes no cgroup of the manager's slices by
//! hand.

use std::io;
use std::path::PathBuf;
use velarx_limit_core::{
    cpu_max, cpuset_mask, limit_of, quota_per_sec, swap_max, weight_of_shares, CpuMax, Limit, Swap,
    MASK_BYTES,
};
use velarx_proto::pod::PodResources;
use velarx_wire::sdbus::{self, Property};

/// A property that is not set: the manager's `UINT64_MAX`.
const UNSET: u64 = u64::MAX;

/// The name of the slice of the pod `pod` below the slice `parent`
/// (`NAME.slice`): `NAME-velarx_pod_<id>.slice`, which the manager puts in
/// `NAME.slice`.
pub fn slice_name(parent: &str, pod: &str) -> Result<String, String> {
    let stem = parent
        .strip_suffix(".slice")
        .filter(|s| !s.is_empty())
        .filter(|s| {
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        })
        .ok_or_else(|| {
            format!(
                "invalid cgroup parent `{parent}`: the systemd cgroup manager takes a slice \
                 (NAME.slice)"
            )
        })?;
    if pod.is_empty() || !pod.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!("not a pod id: {pod}"));
    }
    // (the root slice is `-.slice`: its children have no prefix)
    Ok(match stem {
        "-" => format!("velarx_pod_{pod}.slice"),
        stem => format!("{stem}-velarx_pod_{pod}.slice"),
    })
}

/// The cgroup of the slice `name`, relative to the cgroup file system as
/// the manager puts it: below its parents (`a-b-c.slice` is in `a-b.slice`,
/// in `a.slice`), and, for the manager of a user, below the user's service.
pub fn cgroup_path(name: &str) -> Result<String, velarx_base::ids::IdsError> {
    let stem = name.strip_suffix(".slice").unwrap_or(name);
    let parts: Vec<&str> = if stem == "-" {
        Vec::new()
    } else {
        stem.split('-').collect()
    };
    let mut path = if crate::manager::system_manager()? {
        String::new()
    } else {
        let uid = velarx_base::ids::host_uid()?;
        format!("/user.slice/user-{uid}.slice/user@{uid}.service")
    };
    for i in 1..=parts.len() {
        path.push_str(&format!("/{}.slice", parts[..i].join("-")));
    }
    Ok(path)
}

/// Whether a process is in the slice `name` (`populated 1` of its
/// `cgroup.events`; a slice that is not there has none).
pub fn populated(name: &str) -> Result<bool, velarx_base::ids::IdsError> {
    Ok(std::fs::read_to_string(format!(
        "/sys/fs/cgroup{}/cgroup.events",
        cgroup_path(name)?
    ))
    .is_ok_and(|e| e.lines().any(|l| l == "populated 1")))
}

/// The mask of a list of CPUs (or memory nodes), `0-3,5`: bit `n` of byte
/// `n / 8`.
pub fn cpu_mask(list: &str) -> Result<Vec<u8>, String> {
    let mut mask = [0; MASK_BYTES];
    match cpuset_mask(list.as_bytes(), &mut mask) {
        Some(n) => Ok(mask[..n].to_vec()),
        None => Err(format!("invalid cpuset `{list}`")),
    }
}

/// The properties of a slice with `limits`: those that are set, and with
/// `all` (a change) the others as not set, so that a limit that is gone from
/// the pod is gone from the unit.
pub fn properties(limits: &PodResources, all: bool) -> Result<Vec<Property>, String> {
    let mut props = Vec::new();
    let mut put = |name: &'static str, value: Option<u64>| {
        if let Some(v) = value.or(all.then_some(UNSET)) {
            props.push(Property::U64(name, v));
        }
    };
    let (memory, swap) = (limits.memory.unwrap_or(0), limits.memory_swap.unwrap_or(0));
    let invalid =
        |what: &str, value: i64| format!("the {what} limit {value} of the pod is not one");
    let memory_max = match limit_of(memory) {
        Limit::Bytes(m) => Some(m),
        Limit::Unset | Limit::Unlimited => None,
        Limit::Invalid => return Err(invalid("memory", memory)),
    };
    put("MemoryMax", memory_max);
    // (the limit counts memory and swap together, the property the swap)
    let swap_max = match swap_max(memory, swap) {
        Swap::Max(s) => Some(s),
        Swap::Unlimited => None,
        Swap::Invalid => return Err(invalid("memory and swap", swap)),
    };
    put("MemorySwapMax", swap_max);
    // (CPU shares are 2 to 262144, the weight 1 to 10000)
    put(
        "CPUWeight",
        Some(weight_of_shares(limits.cpu_shares.unwrap_or(0))).filter(|w| *w > 0),
    );
    let quota = limits.cpu_quota.unwrap_or(0);
    let per_sec = match cpu_max(quota, limits.cpu_period.unwrap_or(0)) {
        CpuMax::Quota { quota, period } => Some(quota_per_sec(quota, period)),
        CpuMax::Unlimited => None,
        CpuMax::Invalid => return Err(invalid("CPU quota", quota)),
    };
    put("CPUQuotaPerSecUSec", per_sec);
    put(
        "CPUQuotaPeriodUSec",
        limits
            .cpu_period
            .filter(|p| *p > 0)
            .filter(|_| per_sec.is_some()),
    );
    // (podman gives the weight to IOWeight as it is)
    put(
        "IOWeight",
        limits.blkio_weight.filter(|w| *w > 0).map(u64::from),
    );
    for (name, set) in [
        ("AllowedCPUs", &limits.cpuset_cpus),
        ("AllowedMemoryNodes", &limits.cpuset_mems),
    ] {
        let mask = match set {
            Some(list) => cpu_mask(list)?,
            None => Vec::new(),
        };
        if !mask.is_empty() || all {
            props.push(Property::Bytes(name, mask));
        }
    }
    // (the devices are the `/dev/block/MAJOR:MINOR` podman names them by)
    for (name, list) in [
        ("IODeviceWeight", &limits.blkio_weight_device),
        ("IOReadBandwidthMax", &limits.device_read_bps),
        ("IOWriteBandwidthMax", &limits.device_write_bps),
    ] {
        let devices: Vec<(String, u64)> = list
            .iter()
            .filter(|d| d.value > 0)
            .map(|d| (format!("/dev/block/{}:{}", d.major, d.minor), d.value))
            .collect();
        if !devices.is_empty() || all {
            props.push(Property::Devices(name, devices));
        }
    }
    Ok(props)
}

/// The private socket of the manager of this process.
fn socket() -> Result<PathBuf, velarx_base::ids::IdsError> {
    sdbus::manager_socket(crate::manager::system_manager()?)
}

/// Make the slice `name` with `limits`; one that is there is as it was.
pub fn start(name: &str, pod: &str, limits: &PodResources) -> Result<(), String> {
    let mut props = vec![
        Property::Str("Description", format!("velarx pod {pod}")),
        Property::Str("CollectMode", "inactive-or-failed".into()),
    ];
    props.extend(properties(limits, false)?);
    match sdbus::start_unit_at(&socket().map_err(|e| e.to_string())?, name, &props, true) {
        Err(e) if sdbus::unit_exists(&e) => Ok(()),
        r => r.map_err(|e| format!("systemd did not make the slice {name}: {e}")),
    }
}

/// Change the limits of the slice `name` to `limits`.
pub fn update(name: &str, limits: &PodResources) -> Result<(), String> {
    sdbus::set_properties_at(
        &socket().map_err(|e| e.to_string())?,
        name,
        &properties(limits, true)?,
    )
    .map_err(|e| io_text(name, &e))
}

/// Stop the slice `name` (it is empty when the pod's containers are gone).
pub fn stop(name: &str) -> io::Result<()> {
    sdbus::stop_unit_at(&socket().map_err(io::Error::other)?, name)
}

/// The pod slices this process knows and the limits each has: a container
/// that starts alone asks the manager for a scope in the slice of its pod,
/// which the manager would make without limits when the slice is gone (the
/// manager restarted, or the last container of the pod ended).
#[derive(Default)]
pub struct Slices(std::sync::Mutex<std::collections::HashMap<String, (String, PodResources)>>);

impl Slices {
    pub fn remember(&self, name: &str, pod: &str, limits: &PodResources) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string(), (pod.to_string(), limits.clone()));
    }

    pub fn forget(&self, name: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
    }

    /// The slice, its pod and its limits for the systemd cgroup path of a
    /// container (`slice:prefix:name`), when it is the slice of a pod.
    fn of_path(&self, cgroups_path: &str) -> Option<(String, String, PodResources)> {
        let slice = cgroups_path.split(':').next()?;
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (pod, limits) = map.get(slice)?;
        Some((slice.to_string(), pod.clone(), limits.clone()))
    }

    /// Before the scope of a container of a pod is asked for: the slice of
    /// the pod is there with its limits.
    pub fn ensure(&self, cgroups_path: &str) -> Result<(), String> {
        let Some((name, pod, limits)) = self.of_path(cgroups_path) else {
            return Ok(());
        };
        start(&name, &pod, &limits)?;
        // (one the manager made by itself exists without them)
        update(&name, &limits)
    }
}

fn io_text(name: &str, e: &io::Error) -> String {
    format!("systemd did not change the slice {name}: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::pod::PodDeviceLimit;

    const P: &str = "0123456789abcdef";

    #[test]
    fn the_slice_of_a_pod_is_below_its_parent() {
        assert_eq!(
            slice_name("kubepods-burstable-podX.slice", P).unwrap(),
            format!("kubepods-burstable-podX-velarx_pod_{P}.slice")
        );
        assert_eq!(
            slice_name("-.slice", P).unwrap(),
            format!("velarx_pod_{P}.slice")
        );
        for bad in [".slice", "x", "/x.slice", "a b.slice", "x.scope"] {
            assert!(slice_name(bad, P).is_err(), "{bad}");
        }
        assert!(slice_name("a.slice", "../x").is_err());
    }

    #[test]
    fn a_container_path_finds_the_slice_of_its_pod() {
        let slices = Slices::default();
        let limits = PodResources {
            memory: Some(100),
            ..Default::default()
        };
        slices.remember("k-velarx_pod_p1.slice", "p1", &limits);
        let (name, pod, l) = slices.of_path("k-velarx_pod_p1.slice:velarx:c1").unwrap();
        assert_eq!(
            (name.as_str(), pod.as_str()),
            ("k-velarx_pod_p1.slice", "p1")
        );
        assert_eq!(l.memory, Some(100));
        assert!(slices.of_path("other.slice:velarx:c1").is_none());
        assert!(slices.of_path("/a/b").is_none());
        slices.forget("k-velarx_pod_p1.slice");
        assert!(slices.of_path("k-velarx_pod_p1.slice:velarx:c1").is_none());
    }

    #[test]
    fn a_slice_is_in_the_slices_of_its_name() {
        let path = cgroup_path("a-b_c-velarx_pod_p1.slice").unwrap();
        assert!(
            path.ends_with("/a.slice/a-b_c.slice/a-b_c-velarx_pod_p1.slice"),
            "{path}"
        );
        assert!(cgroup_path("velarx_pod_p1.slice")
            .unwrap()
            .ends_with("/velarx_pod_p1.slice"));
    }

    #[test]
    fn a_cpu_list_is_a_mask() {
        assert_eq!(cpu_mask("0-3,5").unwrap(), [0b0010_1111]);
        assert_eq!(cpu_mask("9").unwrap(), [0, 0b10]);
        assert_eq!(cpu_mask("").unwrap(), Vec::<u8>::new());
        for bad in ["a", "3-1", "1-", "99999", "0;1", "+1"] {
            assert!(cpu_mask(bad).is_err(), "{bad}");
        }
    }

    /// A quota is a quota of a second without wrapping, and a limit that no
    /// cgroup takes is an error, not a smaller or no limit.
    #[test]
    fn a_quota_does_not_wrap_in_the_quota_of_a_second() {
        let quota = |q: i64, period: u64| {
            properties(
                &PodResources {
                    cpu_quota: Some(q),
                    cpu_period: Some(period),
                    ..Default::default()
                },
                false,
            )
        };
        let max = (1i64 << 44) - 1;
        assert_eq!(
            quota(max, 1_000).unwrap()[0],
            Property::U64("CPUQuotaPerSecUSec", max as u64 * 1_000)
        );
        // (2^63 / 10^6 of them: the product wrapped)
        for q in [max + 1, 18_446_744_073_710, i64::MAX, 999, -2] {
            assert!(quota(q, 0).is_err(), "{q}");
        }
        assert!(quota(1_000, 999).is_err());
        let swap = |memory, swap| {
            properties(
                &PodResources {
                    memory,
                    memory_swap: swap,
                    ..Default::default()
                },
                false,
            )
        };
        assert!(swap(Some(100), Some(99)).is_err());
        assert!(swap(None, Some(99)).is_err());
        assert!(swap(Some(-5), None).is_err());
        assert_eq!(
            swap(Some(100), Some(100)).unwrap()[1],
            Property::U64("MemorySwapMax", 0)
        );
    }

    #[test]
    fn the_limits_are_the_properties_of_the_unit() {
        let l = PodResources {
            memory: Some(100),
            memory_swap: Some(150),
            cpu_shares: Some(1024),
            cpu_quota: Some(50_000),
            cpu_period: Some(200_000),
            cpuset_cpus: Some("0-1".into()),
            blkio_weight: Some(50),
            device_read_bps: vec![PodDeviceLimit {
                major: 7,
                minor: 0,
                value: 1 << 20,
                path: String::new(),
            }],
            ..Default::default()
        };
        let p = properties(&l, false).unwrap();
        assert_eq!(
            p,
            [
                Property::U64("MemoryMax", 100),
                Property::U64("MemorySwapMax", 50),
                Property::U64("CPUWeight", 100),
                Property::U64("CPUQuotaPerSecUSec", 250_000),
                Property::U64("CPUQuotaPeriodUSec", 200_000),
                Property::U64("IOWeight", 50),
                Property::Bytes("AllowedCPUs", vec![0b11]),
                Property::Devices(
                    "IOReadBandwidthMax",
                    vec![("/dev/block/7:0".into(), 1 << 20)]
                ),
            ]
        );
        // a change unsets the limits that are gone
        let gone = properties(&PodResources::default(), true).unwrap();
        assert!(gone.contains(&Property::U64("IOWeight", UNSET)));
        assert!(gone.contains(&Property::Devices("IODeviceWeight", Vec::new())));
        // none: nothing at the start, everything unset in a change
        assert!(properties(&PodResources::default(), false)
            .unwrap()
            .is_empty());
        let unset = properties(&PodResources::default(), true).unwrap();
        assert_eq!(unset.len(), 11);
        assert!(unset.contains(&Property::U64("MemoryMax", u64::MAX)));
        assert!(unset.contains(&Property::Bytes("AllowedMemoryNodes", vec![])));
    }
}
