// SPDX-License-Identifier: Apache-2.0
//! The capabilities of a container process, as podman sets them.
//!
//! The bounding set is the default set (or every capability the engine has,
//! for `--privileged` and `--cap-add all`) with `--cap-add` and `--cap-drop`
//! applied.  Root gets it as its effective and permitted sets, with empty
//! inheritable and ambient sets (CVE-2022-27651).  Another user gets only the
//! capabilities it was given with `--cap-add`, in every set: ambient ones
//! survive the exec of the command.  A capability that is both added and
//! dropped is dropped (podman refuses it: a deliberate difference).
//!
//! A default capability that the engine lacks is left out (an engine that
//! itself runs confined has a smaller bounding set); an added one is an error,
//! and so is adding all with dropping all, as in podman.
//!
//! The computation is `velarx-caps-core`, on masks; this is the shell: the
//! names, the bounding set of the engine, and the OCI types.

use oci_spec::runtime::{Capability, LinuxCapabilities, LinuxCapabilitiesBuilder};
use std::collections::HashSet;
use velarx_caps_core::{Refusal, Request};

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

/// podman's default capabilities, as a mask: CHOWN, DAC_OVERRIDE, FOWNER,
/// FSETID, KILL, SETGID, SETUID, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT and
/// SETFCAP (`names` checks the list).
const DEFAULT_CAPABILITIES: u64 = 0x8004_05fb;

/// The number of a capability name, with or without `CAP_`, in any case.
fn parse_capability(name: &str) -> Result<u32, String> {
    let upper = name.to_ascii_uppercase();
    let short = upper.strip_prefix("CAP_").unwrap_or(&upper);
    CAPABILITIES
        .iter()
        .find(|(n, _, _)| *n == short)
        .map(|(_, n, _)| *n)
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

/// [`all_capabilities`] as a mask.
fn bounding_mask() -> u64 {
    bounding().fold(0, |mask, (_, n, _)| mask | 1u64 << n)
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
        bounding_mask(),
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
        bounding_mask(),
        privileged,
        cap_add,
        cap_drop,
        ambient,
        root_user,
    )
}

/// The capabilities of a mask, bit n being capability n.
fn capabilities(mask: u64) -> HashSet<Capability> {
    let have = |n: u32| mask & (1u64 << n) != 0;
    CAPABILITIES
        .iter()
        .filter(|(_, n, _)| have(*n))
        .map(|(_, _, c)| *c)
        .collect()
}

/// The mask of capability names, and whether `all` is among them.
fn parse_mask(names: &[String]) -> Result<(u64, bool), String> {
    let mut mask = 0;
    let mut all = false;
    for name in names {
        if is_all(name) {
            all = true;
        } else {
            mask |= 1u64 << parse_capability(name)?;
        }
    }
    Ok((mask, all))
}

/// The names (`CAP_CHOWN`) of the capabilities of a mask.
fn listed(mask: u64) -> String {
    let names: Vec<_> = CAPABILITIES
        .iter()
        .filter(|(_, n, _)| mask & (1u64 << n) != 0)
        .map(|(name, _, _)| format!("CAP_{name}"))
        .collect();
    names.join(", ")
}

/// `build_capabilities` with `bounding` the bounding set of the engine, as a mask.
fn build_with(
    bounding: u64,
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
    let (add, add_all) = parse_mask(&split(cap_add))?;
    let (drop, drop_all) = parse_mask(&split(cap_drop))?;
    let mut kept = 0;
    for name in split(ambient) {
        kept |= 1u64 << parse_capability(&name)?;
    }
    let request = Request {
        bounding,
        defaults: DEFAULT_CAPABILITIES,
        privileged,
        root: root_user,
        add,
        add_all,
        drop,
        drop_all,
        ambient: kept,
    };
    let sets = velarx_caps_core::sets(&request).map_err(|refusal| match refusal {
        Refusal::AddAndDropAll => {
            "adding all capabilities and dropping all of them is not allowed".to_string()
        }
        Refusal::Add(lacking) => format!(
            "capabilities not in the bounding set of the engine: {}",
            listed(lacking)
        ),
        Refusal::Ambient(lacking) => format!(
            "ambient capabilities not in the bounding set of the engine: {}",
            listed(lacking)
        ),
    })?;
    LinuxCapabilitiesBuilder::default()
        .bounding(capabilities(sets.bounding))
        .effective(capabilities(sets.effective))
        .permitted(capabilities(sets.permitted))
        .inheritable(capabilities(sets.inheritable))
        .ambient(capabilities(sets.ambient))
        .build()
        .map_err(|e| e.to_string())
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

    fn mask_of(caps: &HashSet<Capability>) -> u64 {
        let number = |c: &Capability| CAPABILITIES.iter().find(|e| e.2 == *c).unwrap().1;
        caps.iter().fold(0, |mask, c| mask | 1u64 << number(c))
    }

    fn build_capabilities(
        privileged: bool,
        cap_add: &[String],
        cap_drop: &[String],
        root_user: bool,
    ) -> Result<LinuxCapabilities, String> {
        build_with(
            mask_of(&all_capabilities()),
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
            mask_of(&all_capabilities()),
            privileged,
            cap_add,
            cap_drop,
            ambient,
            root_user,
        )
    }

    /// The names of a list of capabilities, as a set.
    fn named(names: &[&str]) -> HashSet<Capability> {
        capabilities(
            names
                .iter()
                .fold(0, |mask, n| mask | 1u64 << parse_capability(n).unwrap()),
        )
    }

    /// The default capabilities with these added and these taken away.
    fn defaults_with(add: &[&str], take: &[&str]) -> HashSet<Capability> {
        let mut caps = capabilities(DEFAULT_CAPABILITIES);
        caps.extend(named(add));
        caps.retain(|c| !named(take).contains(c));
        caps
    }

    /// Every capability but these.
    fn all_but(take: &[&str]) -> HashSet<Capability> {
        let mut caps = all_capabilities();
        caps.retain(|c| !named(take).contains(c));
        caps
    }

    /// What the five sets are for a request: privileged, root, `--cap-add`,
    /// `--cap-drop`, and the bounding set of the engine; then the bounding,
    /// effective, permitted, inheritable and ambient sets.
    #[test]
    fn the_sets_of_every_kind_of_request() {
        type Sets = [HashSet<Capability>; 5];
        let every = |s: &HashSet<Capability>| -> Sets { std::array::from_fn(|_| s.clone()) };
        let none = HashSet::new;
        // root: the bounding set is its effective and permitted set
        let root = |b: HashSet<Capability>| -> Sets { [b.clone(), b.clone(), b, none(), none()] };
        // another user: the added capabilities are in every set but the bounding one
        let user = |b: HashSet<Capability>, given: HashSet<Capability>| -> Sets {
            [b, given.clone(), given.clone(), given.clone(), given]
        };
        let small = named(&["chown", "kill", "net_raw"]);
        type Row<'a> = (
            bool,
            bool,
            &'a [&'a str],
            &'a [&'a str],
            HashSet<Capability>,
            Sets,
        );
        let rows: Vec<Row> = vec![
            // (privileged, root, add, drop, engine's bounding set, sets)
            (
                false,
                true,
                &[],
                &[],
                all_capabilities(),
                root(defaults_with(&[], &[])),
            ),
            (
                false,
                true,
                &["net_raw"],
                &[],
                all_capabilities(),
                root(defaults_with(&["net_raw"], &[])),
            ),
            (
                false,
                true,
                &[],
                &["chown"],
                all_capabilities(),
                root(defaults_with(&[], &["chown"])),
            ),
            (false, true, &[], &["all"], all_capabilities(), root(none())),
            (
                false,
                true,
                &["kill"],
                &["all"],
                all_capabilities(),
                root(named(&["kill"])),
            ),
            (
                false,
                true,
                &["all"],
                &[],
                all_capabilities(),
                root(all_capabilities()),
            ),
            (
                false,
                true,
                &["all"],
                &["sys_admin"],
                all_capabilities(),
                root(all_but(&["sys_admin"])),
            ),
            (
                true,
                true,
                &[],
                &[],
                all_capabilities(),
                root(all_capabilities()),
            ),
            (
                true,
                true,
                &[],
                &["chown"],
                all_capabilities(),
                root(all_capabilities()),
            ),
            (
                true,
                true,
                &["all"],
                &["all"],
                all_capabilities(),
                root(all_capabilities()),
            ),
            (
                false,
                false,
                &[],
                &[],
                all_capabilities(),
                user(defaults_with(&[], &[]), none()),
            ),
            (
                false,
                false,
                &["net_raw"],
                &[],
                all_capabilities(),
                user(defaults_with(&["net_raw"], &[]), named(&["net_raw"])),
            ),
            (
                false,
                false,
                &["all"],
                &[],
                all_capabilities(),
                every(&all_capabilities()),
            ),
            (
                false,
                false,
                &["all"],
                &["sys_admin"],
                all_capabilities(),
                user(all_but(&["sys_admin"]), all_but(&["sys_admin"])),
            ),
            (
                false,
                false,
                &["kill"],
                &["all"],
                all_capabilities(),
                user(named(&["kill"]), named(&["kill"])),
            ),
            (
                false,
                true,
                &["kill"],
                &["kill"],
                all_capabilities(),
                root(defaults_with(&[], &["kill"])),
            ),
            (
                false,
                false,
                &["chown"],
                &["chown"],
                all_capabilities(),
                user(defaults_with(&[], &["chown"]), none()),
            ),
            (
                true,
                false,
                &[],
                &[],
                all_capabilities(),
                user(all_capabilities(), none()),
            ),
            (
                true,
                false,
                &["net_raw"],
                &[],
                all_capabilities(),
                user(all_capabilities(), named(&["net_raw"])),
            ),
            (
                true,
                false,
                &["chown"],
                &["chown"],
                all_capabilities(),
                user(all_capabilities(), named(&["chown"])),
            ),
            // an engine with a smaller bounding set: the defaults it lacks are
            // left out (an added one it lacks is an error, below)
            (
                false,
                true,
                &[],
                &[],
                small.clone(),
                root(named(&["chown", "kill"])),
            ),
            (
                false,
                true,
                &["net_raw"],
                &[],
                small.clone(),
                root(named(&["chown", "kill", "net_raw"])),
            ),
            (
                false,
                false,
                &[],
                &[],
                small.clone(),
                user(named(&["chown", "kill"]), none()),
            ),
            (
                false,
                true,
                &["all"],
                &[],
                small.clone(),
                root(small.clone()),
            ),
            (true, true, &[], &[], small.clone(), root(small.clone())),
            (
                true,
                false,
                &["kill"],
                &[],
                small.clone(),
                user(small.clone(), named(&["kill"])),
            ),
        ];
        for (privileged, root_user, add, drop, bounding, want) in rows {
            let c = build_with(
                mask_of(&bounding),
                privileged,
                &s(add),
                &s(drop),
                &[],
                root_user,
            )
            .unwrap();
            let got: Sets = [
                c.bounding(),
                c.effective(),
                c.permitted(),
                c.inheritable(),
                c.ambient(),
            ]
            .map(set);
            assert_eq!(
                got, want,
                "privileged {privileged} root {root_user} add {add:?} drop {drop:?}"
            );
        }
    }

    #[test]
    fn names() {
        assert_eq!(parse_capability("CAP_NET_ADMIN"), Ok(12));
        assert_eq!(parse_capability("net_admin"), Ok(12));
        assert_eq!(parse_capability("cap_sys_admin"), Ok(21));
        assert!(parse_capability("CAP_NOPE").is_err());
        assert!(parse_capability("").is_err());
        assert!(parse_capability("CAP_").is_err());
        assert_eq!(listed(1 << 39), "CAP_BPF");
        for (name, n, _) in CAPABILITIES {
            assert_eq!(parse_capability(name), Ok(n));
            assert_eq!(listed(1 << n), format!("CAP_{name}"));
        }
        assert_eq!(
            listed(DEFAULT_CAPABILITIES),
            "CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, \
             CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_SETFCAP"
        );
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
        let want = capabilities(DEFAULT_CAPABILITIES);
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
        assert_eq!(
            set(c.bounding()).len(),
            DEFAULT_CAPABILITIES.count_ones() as usize
        );
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
        assert!(build_with(mask_of(&some), false, &s(&["kill"]), &[], &[], true).is_ok());
        let e = build_with(mask_of(&some), false, &s(&["sys_admin"]), &[], &[], true).unwrap_err();
        assert!(e.contains("bounding set"), "{e}");
        // `all` and --privileged are what there is
        let c = build_with(mask_of(&some), true, &[], &[], &[], true).unwrap();
        let e = build_with(mask_of(&some), false, &[], &[], &s(&["sys_admin"]), true).unwrap_err();
        assert!(e.contains("CAP_SYS_ADMIN"), "{e}");
        assert_eq!(set(c.bounding()), some);
    }

    #[test]
    fn all_added_and_all_dropped_is_refused_as_podman_does() {
        for root in [true, false] {
            let e = build_capabilities(false, &s(&["all"]), &s(&["ALL"]), root).unwrap_err();
            assert!(e.contains("all"), "{e}");
        }
        // --privileged has no drop
        assert!(build_capabilities(true, &s(&["all"]), &s(&["all"]), true).is_ok());
    }

    #[test]
    fn unknown_names_are_errors() {
        assert!(build_capabilities(false, &s(&["CAP_NOPE"]), &[], true).is_err());
        assert!(build_capabilities(false, &[], &s(&["bogus"]), true).is_err());
        assert!(build_capabilities(true, &[], &s(&["bogus"]), true).is_err());
    }
}
