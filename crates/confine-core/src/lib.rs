// SPDX-License-Identifier: Apache-2.0
//! Which confinement a container gets: what `--privileged` and its
//! relatives (`--security-opt seccomp=unconfined`, `unmask=`, the host's
//! `/sys`) turn off, and what stays on.  One decision for the engine's spec
//! builder, and for the CRI, which turns the security context of the
//! kubelet into the options of the engine ([`cri`]).
//!
//! The shell reads the flags (the seccomp profile, the lists of paths) and
//! builds the OCI spec from the [`Decision`]: it keeps the lists of paths
//! itself, with their names, and takes a path out of the defaults by name.
//!
//! The rules, for every request (see `rules`):
//!
//! 1. A container that is not privileged has the device cgroup that denies
//!    everything first; a privileged one has no device rule.
//! 2. It has a seccomp filter unless the profile was asked to be
//!    `unconfined`; a profile that was asked for always applies, the default
//!    one only to a container that is not privileged.
//! 3. It keeps every default masked and read-only path unless an unmask was
//!    asked for; `unmask=ALL` or `--privileged` leave none of the defaults.
//! 4. The `/sys` of a container is read-only unless it is privileged; the
//!    host's `/sys` as a bind has `/sys/kernel` masked unless the container
//!    is privileged, whatever is unmasked (it is not a default path, and
//!    podman masks it after the unmasks).
//! 5. No new privileges is what was asked.
//! 6. Each part of the decision depends on the options that concern it and
//!    on no other: two unrelated options never turn anything off together.
//!
//! Written to be translated (tools/verify): plain structs, enums and
//! booleans, no loop, no closure, no iterator adapter.

/// The seccomp profile asked for (`--security-opt seccomp=`).
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Seccomp {
    /// Nothing named: the default profile.
    Default,
    /// `unconfined`: no filter.
    Unconfined,
    /// A profile of the user.
    Custom,
}

/// What a container asks for.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Request {
    /// `--privileged`.
    pub privileged: bool,
    pub seccomp: Seccomp,
    /// `unmask=ALL`: none of the defaults.
    pub unmask_all: bool,
    /// `unmask=` names paths (other than `ALL`).
    pub unmask_some: bool,
    /// The `/sys` of the container is a bind of the host's (it cannot have a
    /// sysfs of its own).
    pub host_sysfs: bool,
    /// `--security-opt no-new-privileges`.
    pub no_new_privileges: bool,
}

/// The seccomp filter of the container.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Filter {
    Default,
    Custom,
    None,
}

/// Which of the default masked (or read-only) paths a container has.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Paths {
    /// All of them.
    Default,
    /// All of them but those named by `unmask=`.
    Without,
    /// None.
    None,
}

/// The confinement of a container.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Decision {
    /// The device cgroup denies everything first (then allows the devices a
    /// container needs).
    pub deny_all_devices: bool,
    pub seccomp: Filter,
    pub masked: Paths,
    pub readonly: Paths,
    /// `/sys` is read-only.
    pub sys_readonly: bool,
    /// `/sys/kernel` is masked, on top of the default paths.
    pub mask_sys_kernel: bool,
    pub no_new_privileges: bool,
}

/// The confinement a request gets.
pub fn decide(r: &Request) -> Decision {
    let seccomp = match r.seccomp {
        Seccomp::Custom => Filter::Custom,
        Seccomp::Unconfined => Filter::None,
        Seccomp::Default => {
            if r.privileged {
                Filter::None
            } else {
                Filter::Default
            }
        }
    };
    let paths = if r.privileged || r.unmask_all {
        Paths::None
    } else if r.unmask_some {
        Paths::Without
    } else {
        Paths::Default
    };
    let mask_sys_kernel = if r.privileged { false } else { r.host_sysfs };
    let confined = !r.privileged;
    Decision {
        deny_all_devices: confined,
        seccomp,
        masked: paths,
        readonly: paths,
        sys_readonly: confined,
        mask_sys_kernel,
        no_new_privileges: r.no_new_privileges,
    }
}

pub mod cri;

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
