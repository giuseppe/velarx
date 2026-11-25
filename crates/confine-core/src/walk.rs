// SPDX-License-Identifier: Apache-2.0
//! Every request, and the rules (see `rules`) checked on each answer: three
//! seccomp profiles and five options that are on or off.

use super::rules::{check, check_cri};
use super::*;

/// The requests checked.
fn walk() -> usize {
    let mut checked = 0;
    for seccomp in [Seccomp::Default, Seccomp::Unconfined, Seccomp::Custom] {
        for flags in 0..32u32 {
            let r = Request {
                privileged: flags & 1 != 0,
                seccomp,
                unmask_all: flags & 2 != 0,
                unmask_some: flags & 4 != 0,
                host_sysfs: flags & 8 != 0,
                no_new_privileges: flags & 16 != 0,
            };
            check(&r, &decide(&r));
            checked += 1;
        }
    }
    checked
}

#[test]
fn every_request() {
    assert_eq!(walk(), 3 * 32);
}

#[test]
fn every_context() {
    use cri::{Context, Profile};
    let mut checked = 0;
    for seccomp in [
        Profile::Absent,
        Profile::RuntimeDefault,
        Profile::Unconfined,
        Profile::Localhost,
    ] {
        for flags in 0..4u32 {
            let c = Context {
                present: flags & 1 != 0,
                privileged: flags & 2 != 0,
                seccomp,
            };
            check_cri(&c, &cri::from_cri(&c));
            checked += 1;
        }
    }
    assert_eq!(checked, 4 * 4);
}
