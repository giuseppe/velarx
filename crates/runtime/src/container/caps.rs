// SPDX-License-Identifier: Apache-2.0
//! The capabilities of a container process, as podman sets them.
//!
//! The bounding set is the default set (or every capability the engine has,
//! for `--privileged` and `--cap-add all`) with `--cap-add` and `--cap-drop`
//! applied.  Root gets it as its effective and permitted sets, with empty
//! inheritable and ambient sets (CVE-2022-27651).  Another user gets only the
//! capabilities it was given with `--cap-add`, in every set: ambient ones
//! survive the exec of the command.

use oci_spec::runtime::{Capability, LinuxCapabilities, LinuxCapabilitiesBuilder};
use std::collections::HashSet;

/// The names and numbers of the capabilities that the OCI spec knows.
const CAPABILITIES: [(&str, u32, Capability); 41] = [
    ("CHOWN", 0, Capability::Chown),
    ("DAC_OVERRIDE", 1, Capability::DacOverride),
    ("DAC_READ_SEARCH", 2, Capability::DacReadSearch),
    ("FOWNER", 3, Capability::Fowner),
    ("FSETID", 4, Capability::Fsetid),
    ("KILL", 5, Capability::Kill),
    ("SETGID", 6, Capability::Setgid),
    ("SETUID", 7, Capability::Setuid),
    ("SETPCAP", 8, Capability::Setpcap),
    ("LINUX_IMMUTABLE", 9, Capability::LinuxImmutable),
    ("NET_BIND_SERVICE", 10, Capability::NetBindService),
    ("NET_BROADCAST", 11, Capability::NetBroadcast),
    ("NET_ADMIN", 12, Capability::NetAdmin),
    ("NET_RAW", 13, Capability::NetRaw),
    ("IPC_LOCK", 14, Capability::IpcLock),
    ("IPC_OWNER", 15, Capability::IpcOwner),
    ("SYS_MODULE", 16, Capability::SysModule),
    ("SYS_RAWIO", 17, Capability::SysRawio),
    ("SYS_CHROOT", 18, Capability::SysChroot),
    ("SYS_PTRACE", 19, Capability::SysPtrace),
    ("SYS_PACCT", 20, Capability::SysPacct),
    ("SYS_ADMIN", 21, Capability::SysAdmin),
    ("SYS_BOOT", 22, Capability::SysBoot),
    ("SYS_NICE", 23, Capability::SysNice),
    ("SYS_RESOURCE", 24, Capability::SysResource),
    ("SYS_TIME", 25, Capability::SysTime),
    ("SYS_TTY_CONFIG", 26, Capability::SysTtyConfig),
    ("MKNOD", 27, Capability::Mknod),
    ("LEASE", 28, Capability::Lease),
    ("AUDIT_WRITE", 29, Capability::AuditWrite),
    ("AUDIT_CONTROL", 30, Capability::AuditControl),
    ("SETFCAP", 31, Capability::Setfcap),
    ("MAC_OVERRIDE", 32, Capability::MacOverride),
    ("MAC_ADMIN", 33, Capability::MacAdmin),
    ("SYSLOG", 34, Capability::Syslog),
    ("WAKE_ALARM", 35, Capability::WakeAlarm),
    ("BLOCK_SUSPEND", 36, Capability::BlockSuspend),
    ("AUDIT_READ", 37, Capability::AuditRead),
    ("PERFMON", 38, Capability::Perfmon),
    ("BPF", 39, Capability::Bpf),
    ("CHECKPOINT_RESTORE", 40, Capability::CheckpointRestore),
];

/// podman's default capabilities.
pub const DEFAULT_CAPABILITIES: [Capability; 11] = [
    Capability::Chown,
    Capability::DacOverride,
    Capability::Fowner,
    Capability::Fsetid,
    Capability::Kill,
    Capability::NetBindService,
    Capability::Setfcap,
    Capability::Setgid,
    Capability::Setpcap,
    Capability::Setuid,
    Capability::SysChroot,
];

/// A capability name, with or without `CAP_`, in any case.
pub fn parse_capability(name: &str) -> Result<Capability, String> {
    let upper = name.to_ascii_uppercase();
    let short = upper.strip_prefix("CAP_").unwrap_or(&upper);
    CAPABILITIES
        .iter()
        .find(|(n, _, _)| *n == short)
        .map(|(_, _, c)| *c)
        .ok_or_else(|| format!("unknown capability `{name}`"))
}

/// `CAP_NAME` of a capability.
pub fn capability_name(cap: Capability) -> String {
    CAPABILITIES
        .iter()
        .find(|(_, _, c)| *c == cap)
        .map(|(n, _, _)| format!("CAP_{n}"))
        .unwrap_or_default()
}

/// The capabilities of the bounding set of this process.
fn bounding() -> impl Iterator<Item = &'static (&'static str, u32, Capability)> {
    use rustix::thread::{capability_is_in_bounding_set, CapabilitySet};
    CAPABILITIES.iter().filter(|(_, n, _)| {
        capability_is_in_bounding_set(CapabilitySet::from_bits_retain(1u64 << n)).unwrap_or(false)
    })
}

/// Every capability the engine can give: the bounding set of the daemon.
pub fn all_capabilities() -> HashSet<Capability> {
    bounding().map(|(_, _, c)| *c).collect()
}

/// [`all_capabilities`] by name (`CAP_CHOWN`), as a spec has them.
pub fn bounding_names() -> Vec<String> {
    bounding().map(|(n, _, _)| format!("CAP_{n}")).collect()
}

fn is_all(name: &str) -> bool {
    name.eq_ignore_ascii_case("all")
}

/// The capabilities of a container process; `root_user` is uid 0 in the
/// container.  Unknown names are an error.
pub fn build_capabilities(
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
    root_user: bool,
) -> Result<LinuxCapabilities, String> {
    build_with(
        all_capabilities(),
        privileged,
        cap_add,
        cap_drop,
        &[],
        root_user,
    )
}

/// [`build_capabilities`] with `ambient` capabilities: added to the bounding
/// set and in every set of the process, the ambient one included, for root
/// too (the CRI's `add_ambient_capabilities`).  One that `cap_drop` names is
/// dropped from all of them, as the CRI says of a dropped capability.
pub fn build_capabilities_with_ambient(
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
    ambient: &[String],
    root_user: bool,
) -> Result<LinuxCapabilities, String> {
    build_with(
        all_capabilities(),
        privileged,
        cap_add,
        cap_drop,
        ambient,
        root_user,
    )
}

/// `build_capabilities` with `all` the bounding set of the engine.
fn build_with(
    all: HashSet<Capability>,
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
    ambient: &[String],
    root_user: bool,
) -> Result<LinuxCapabilities, String> {
    // podman's CLI takes lists: `--cap-add net_raw,sys_time`
    let split = |v: &[String]| -> Vec<String> {
        v.iter()
            .flat_map(|x| x.split(','))
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    };
    let (cap_add, cap_drop) = (split(cap_add), split(cap_drop));
    let mut added = HashSet::new();
    for name in cap_add.iter().filter(|n| !is_all(n)) {
        let cap = parse_capability(name)?;
        // the runtime could not give it: the create fails, not the start
        if !all.contains(&cap) {
            return Err(format!(
                "the capability `{}` is not in the bounding set of the engine",
                capability_name(cap)
            ));
        }
        added.insert(cap);
    }
    let mut dropped = HashSet::new();
    for name in cap_drop.iter().filter(|n| !is_all(n)) {
        dropped.insert(parse_capability(name)?);
    }
    let mut kept = HashSet::new();
    for name in split(ambient) {
        let cap = parse_capability(&name)?;
        if !all.contains(&cap) {
            return Err(format!(
                "the ambient capability `{}` is not in the bounding set of the engine",
                capability_name(cap)
            ));
        }
        kept.insert(cap);
    }

    let add_all = cap_add.iter().any(|n| is_all(n));
    let mut caps: HashSet<Capability> = if privileged || add_all {
        all.clone()
    } else if cap_drop.iter().any(|n| is_all(n)) {
        HashSet::new()
    } else {
        DEFAULT_CAPABILITIES.into_iter().collect()
    };
    caps.extend(added.iter().copied());
    if !privileged {
        caps.retain(|c| !dropped.contains(c));
        kept.retain(|c| !dropped.contains(c));
    }
    caps.extend(kept.iter().copied());

    let builder = LinuxCapabilitiesBuilder::default().bounding(caps.clone());
    let builder = if root_user {
        builder
            .effective(caps.clone())
            .permitted(caps)
            .inheritable(kept.clone())
            .ambient(kept)
    } else {
        let mut given: HashSet<Capability> = match add_all {
            true => caps,
            false => caps.intersection(&added).copied().collect(),
        };
        given.extend(kept);
        builder
            .effective(given.clone())
            .permitted(given.clone())
            .inheritable(given.clone())
            .ambient(given)
    };
    builder.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn set(c: &Option<HashSet<Capability>>) -> HashSet<Capability> {
        c.clone().unwrap_or_default()
    }

    // The tests below see every capability as in the bounding set of the
    // engine, whatever that of the test process is (a container drops some):
    // `only_what_the_engine_has` tests a smaller one.
    fn all_capabilities() -> HashSet<Capability> {
        CAPABILITIES.iter().map(|(_, _, c)| *c).collect()
    }

    fn build_capabilities(
        privileged: bool,
        cap_add: &[String],
        cap_drop: &[String],
        root_user: bool,
    ) -> Result<LinuxCapabilities, String> {
        build_with(
            all_capabilities(),
            privileged,
            cap_add,
            cap_drop,
            &[],
            root_user,
        )
    }

    fn build_capabilities_with_ambient(
        privileged: bool,
        cap_add: &[String],
        cap_drop: &[String],
        ambient: &[String],
        root_user: bool,
    ) -> Result<LinuxCapabilities, String> {
        build_with(
            all_capabilities(),
            privileged,
            cap_add,
            cap_drop,
            ambient,
            root_user,
        )
    }

    #[test]
    fn names() {
        assert_eq!(parse_capability("CAP_NET_ADMIN"), Ok(Capability::NetAdmin));
        assert_eq!(parse_capability("net_admin"), Ok(Capability::NetAdmin));
        assert_eq!(parse_capability("cap_sys_admin"), Ok(Capability::SysAdmin));
        assert!(parse_capability("CAP_NOPE").is_err());
        assert!(parse_capability("").is_err());
        assert!(parse_capability("CAP_").is_err());
        assert_eq!(capability_name(Capability::Bpf), "CAP_BPF");
        for (n, _, c) in CAPABILITIES {
            assert_eq!(parse_capability(n), Ok(c));
            assert_eq!(capability_name(c), format!("CAP_{n}"));
        }
        // the numbers are those of the kernel, in order
        for (i, (_, n, _)) in CAPABILITIES.iter().enumerate() {
            assert_eq!(*n as usize, i);
        }
    }

    #[test]
    fn ambient_capabilities_are_in_every_set_for_any_user() {
        for root in [true, false] {
            let c = build_capabilities_with_ambient(
                false,
                &[],
                &s(&["chown"]),
                &s(&["CAP_NET_RAW"]),
                root,
            )
            .unwrap();
            let raw = HashSet::from([Capability::NetRaw]);
            assert!(set(c.bounding()).contains(&Capability::NetRaw), "{root}");
            assert!(!set(c.bounding()).contains(&Capability::Chown), "{root}");
            assert_eq!(set(c.ambient()), raw, "{root}");
            assert_eq!(set(c.inheritable()), raw, "{root}");
            assert!(set(c.effective()).contains(&Capability::NetRaw), "{root}");
            assert!(set(c.permitted()).contains(&Capability::NetRaw), "{root}");
            // `drop: [ALL]` takes the defaults away, not what is asked for;
            // a capability dropped by name is not given back as an ambient one
            let c =
                build_capabilities_with_ambient(false, &[], &s(&["all"]), &s(&["NET_RAW"]), root)
                    .unwrap();
            assert_eq!(set(c.bounding()), set(c.ambient()), "{root}");
            let c = build_capabilities_with_ambient(
                false,
                &[],
                &s(&["net_raw"]),
                &s(&["NET_RAW"]),
                root,
            )
            .unwrap();
            assert!(!set(c.bounding()).contains(&Capability::NetRaw), "{root}");
            assert!(set(c.ambient()).is_empty(), "{root}");
            assert!(set(c.effective()).is_disjoint(&raw), "{root}");
        }
    }

    #[test]
    fn defaults_for_root() {
        let c = build_capabilities(false, &[], &[], true).unwrap();
        let want: HashSet<_> = DEFAULT_CAPABILITIES.into_iter().collect();
        assert_eq!(set(c.bounding()), want);
        assert_eq!(set(c.effective()), want);
        assert_eq!(set(c.permitted()), want);
        assert!(set(c.inheritable()).is_empty());
        assert!(set(c.ambient()).is_empty());
        assert!(!want.contains(&Capability::NetRaw));
        assert!(!want.contains(&Capability::Mknod));
    }

    #[test]
    fn a_user_gets_only_the_added_capabilities() {
        let c = build_capabilities(false, &[], &[], false).unwrap();
        assert_eq!(set(c.bounding()).len(), DEFAULT_CAPABILITIES.len());
        assert!(set(c.effective()).is_empty());
        assert!(set(c.permitted()).is_empty());
        assert!(set(c.ambient()).is_empty());
        let c = build_capabilities(false, &s(&["net_raw", "CAP_CHOWN"]), &[], false).unwrap();
        let want: HashSet<_> = [Capability::NetRaw, Capability::Chown]
            .into_iter()
            .collect();
        assert_eq!(set(c.effective()), want);
        assert_eq!(set(c.permitted()), want);
        assert_eq!(set(c.inheritable()), want);
        assert_eq!(set(c.ambient()), want);
        assert!(set(c.bounding()).contains(&Capability::NetRaw));
        // all of them with `all`, none with --privileged
        let c = build_capabilities(false, &s(&["all"]), &[], false).unwrap();
        assert_eq!(set(c.ambient()), all_capabilities());
        let c = build_capabilities(true, &[], &[], false).unwrap();
        assert!(set(c.effective()).is_empty());
        assert_eq!(set(c.bounding()), all_capabilities());
    }

    #[test]
    fn add_and_drop() {
        let c = build_capabilities(false, &s(&["NET_ADMIN"]), &s(&["chown", "cap_kill"]), true)
            .unwrap();
        let b = set(c.bounding());
        assert!(b.contains(&Capability::NetAdmin));
        assert!(!b.contains(&Capability::Chown));
        assert!(!b.contains(&Capability::Kill));
        let c =
            build_capabilities(false, &s(&["net_raw, sys_time"]), &s(&["kill,"]), true).unwrap();
        let b = set(c.bounding());
        assert!(b.contains(&Capability::NetRaw) && b.contains(&Capability::SysTime));
        assert!(!b.contains(&Capability::Kill));
        let c = build_capabilities(false, &s(&["kill"]), &s(&["ALL"]), true).unwrap();
        assert_eq!(set(c.bounding()), [Capability::Kill].into_iter().collect());
        // a dropped capability wins over an added one
        let c = build_capabilities(false, &s(&["kill"]), &s(&["kill"]), true).unwrap();
        assert!(!set(c.bounding()).contains(&Capability::Kill));
    }

    #[test]
    fn all_and_privileged() {
        let all = all_capabilities();
        let c = build_capabilities(false, &s(&["all"]), &s(&["sys_admin"]), true).unwrap();
        let mut want = all.clone();
        want.remove(&Capability::SysAdmin);
        assert_eq!(set(c.bounding()), want);
        // --cap-drop does not apply to --privileged
        let c = build_capabilities(true, &[], &s(&["sys_admin"]), true).unwrap();
        assert_eq!(set(c.bounding()), all);
        assert!(set(c.ambient()).is_empty());
        assert!(set(c.inheritable()).is_empty());
    }

    #[test]
    fn only_what_the_engine_has() {
        let some: HashSet<_> = [Capability::Chown, Capability::Kill].into_iter().collect();
        assert!(build_with(some.clone(), false, &s(&["kill"]), &[], &[], true).is_ok());
        let e = build_with(some.clone(), false, &s(&["sys_admin"]), &[], &[], true).unwrap_err();
        assert!(e.contains("bounding set"), "{e}");
        // `all` and --privileged are what there is
        let c = build_with(some.clone(), true, &[], &[], &[], true).unwrap();
        let e = build_with(some.clone(), false, &[], &[], &s(&["sys_admin"]), true).unwrap_err();
        assert!(e.contains("CAP_SYS_ADMIN"), "{e}");
        assert_eq!(set(c.bounding()), some);
    }

    #[test]
    fn unknown_names_are_errors() {
        assert!(build_capabilities(false, &s(&["CAP_NOPE"]), &[], true).is_err());
        assert!(build_capabilities(false, &[], &s(&["bogus"]), true).is_err());
        assert!(build_capabilities(true, &[], &s(&["bogus"]), true).is_err());
    }
}
