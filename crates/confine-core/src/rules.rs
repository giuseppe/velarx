// SPDX-License-Identifier: Apache-2.0
//! The rules of the confinement, checked on every answer of `decide`.  They
//! are stated by what a request means, not by how `decide` computes, so
//! that a computation that is wrong in another way than the one it was
//! written for still fails one.

use super::*;

/// What a part of the decision depends on: whether the option `i` of the
/// request (see `change`) can change the part `part` of the answer.
fn concerns(part: usize, i: usize) -> bool {
    // the options: 0 privileged, 1 seccomp, 2 unmask all, 3 unmask some,
    // 4 host sysfs, 5 no new privileges
    match part {
        // the device cgroup, and /sys read-only
        0 | 4 => i == 0,
        // seccomp
        1 => i == 0 || i == 1,
        // the masked and the read-only paths
        2 | 3 => i <= 3 && i != 1,
        // /sys/kernel
        5 => i == 0 || i == 4,
        // no new privileges
        _ => i == 5,
    }
}

/// The request with the option `i` changed.
fn change(r: &Request, i: usize) -> Request {
    let mut c = *r;
    match i {
        0 => c.privileged = !r.privileged,
        1 => {
            c.seccomp = match r.seccomp {
                Seccomp::Default => Seccomp::Unconfined,
                Seccomp::Unconfined => Seccomp::Custom,
                Seccomp::Custom => Seccomp::Default,
            }
        }
        2 => c.unmask_all = !r.unmask_all,
        3 => c.unmask_some = !r.unmask_some,
        4 => c.host_sysfs = !r.host_sysfs,
        _ => c.no_new_privileges = !r.no_new_privileges,
    }
    c
}

/// The parts of a decision, by the number `concerns` knows them by.
fn same(part: usize, a: &Decision, b: &Decision) -> bool {
    match part {
        0 => a.deny_all_devices == b.deny_all_devices,
        1 => a.seccomp == b.seccomp,
        2 => a.masked == b.masked,
        3 => a.readonly == b.readonly,
        4 => a.sys_readonly == b.sys_readonly,
        5 => a.mask_sys_kernel == b.mask_sys_kernel,
        _ => a.no_new_privileges == b.no_new_privileges,
    }
}

/// Checks the answer of `decide` for a request; a rule that fails panics
/// with its words, and the request.
pub fn check(r: &Request, d: &Decision) {
    let what = || format!("{r:?}: {d:?}");
    let unmask = r.unmask_all || r.unmask_some;

    // The device cgroup denies all first, but for a privileged container.
    assert_eq!(d.deny_all_devices, !r.privileged, "devices: {}", what());

    // Seccomp: a profile that was asked for applies, `unconfined` is none,
    // the default one is for the container that is not privileged.
    if r.seccomp == Seccomp::Custom {
        assert_eq!(d.seccomp, Filter::Custom, "custom: {}", what());
    }
    if r.seccomp == Seccomp::Unconfined {
        assert_eq!(d.seccomp, Filter::None, "unconfined: {}", what());
    }
    if r.seccomp == Seccomp::Default {
        let want = if r.privileged {
            Filter::None
        } else {
            Filter::Default
        };
        assert_eq!(d.seccomp, want, "default: {}", what());
    }
    if !r.privileged && r.seccomp != Seccomp::Unconfined {
        assert_ne!(d.seccomp, Filter::None, "no filter, none asked: {}", what());
    }

    // The default paths: all of them kept unless an unmask was asked for,
    // none for ALL and for a privileged container.
    for paths in [d.masked, d.readonly] {
        if !r.privileged && !unmask {
            assert_eq!(paths, Paths::Default, "kept: {}", what());
        }
        if !r.privileged && !r.unmask_all && r.unmask_some {
            assert_ne!(paths, Paths::None, "unmasked more than asked: {}", what());
        }
        if r.privileged || r.unmask_all {
            assert_eq!(paths, Paths::None, "none: {}", what());
        }
        if !r.privileged && !r.unmask_all && r.unmask_some {
            assert_eq!(paths, Paths::Without, "without: {}", what());
        }
    }
    assert_eq!(d.masked, d.readonly, "the two lists: {}", what());

    // /sys is read-only unless privileged; the host's /sys has /sys/kernel
    // masked unless privileged, whatever is unmasked.
    assert_eq!(d.sys_readonly, !r.privileged, "/sys: {}", what());
    if r.host_sysfs && !r.privileged {
        assert!(d.mask_sys_kernel, "the host's /sys: {}", what());
    }
    if r.privileged || !r.host_sysfs {
        assert!(
            !d.mask_sys_kernel,
            "/sys/kernel masked for nothing: {}",
            what()
        );
    }

    // No new privileges is what was asked.
    assert_eq!(d.no_new_privileges, r.no_new_privileges, "nnp: {}", what());

    // Each part depends on the options that concern it only.
    for i in 0..6 {
        let other = decide(&change(r, i));
        for part in 0..7 {
            if !concerns(part, i) {
                assert!(
                    same(part, d, &other),
                    "part {part} follows option {i}: {}",
                    what()
                );
            }
        }
    }
}

/// Checks the answer of `from_cri` for a context.
pub fn check_cri(c: &cri::Context, a: &cri::Ask) {
    use cri::Profile;
    let what = || format!("{c:?}: {a:?}");
    let named = c.present && !c.privileged;
    // No context: the engine's defaults.
    if !c.present {
        assert_eq!(a.seccomp, Seccomp::Default, "no context: {}", what());
    }
    // A privileged container has no profile, the one named included, and
    // no lists of paths.
    if c.present && c.privileged {
        assert_eq!(a.seccomp, Seccomp::Unconfined, "privileged: {}", what());
    }
    if c.privileged {
        assert!(!a.own_paths, "privileged paths: {}", what());
    }
    // The lists of the kubelet are the container's only where there is a
    // context with lists: none without one, all of them in a context.
    if a.own_paths {
        assert!(c.present, "paths of no context: {}", what());
    }
    if named {
        assert!(a.own_paths, "paths of the context: {}", what());
    }
    // What the profile names is what applies: the default profile and a
    // file never become no profile, `Unconfined` is always none, a file is
    // always a profile of the user.
    if named && c.seccomp == Profile::RuntimeDefault {
        assert_eq!(a.seccomp, Seccomp::Default, "default: {}", what());
    }
    if named && c.seccomp == Profile::Localhost {
        assert_eq!(a.seccomp, Seccomp::Custom, "file: {}", what());
    }
    if c.present && c.seccomp == Profile::Unconfined {
        assert_eq!(a.seccomp, Seccomp::Unconfined, "unconfined: {}", what());
    }
    // A profile that is not named is none, as the API says of the
    // deprecated path.
    if named && c.seccomp == Profile::Absent {
        assert_eq!(a.seccomp, Seccomp::Unconfined, "absent: {}", what());
    }
}
