// SPDX-License-Identifier: Apache-2.0
//! What the security context of a container of the CRI asks of the engine:
//! the seccomp profile, and whether the lists of masked and read-only
//! paths of the kubelet replace the defaults.  The answer is the request of
//! the engine's own options (`--security-opt seccomp=`, `unmask=ALL`), which
//! [`crate::decide`] turns into the confinement.

use crate::Seccomp;

/// The seccomp profile of a security context.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Profile {
    /// The context names none.
    Absent,
    RuntimeDefault,
    Unconfined,
    /// A file of the host.
    Localhost,
}

/// A security context of a container.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Context {
    /// The container has a security context at all.
    pub present: bool,
    pub privileged: bool,
    pub seccomp: Profile,
}

/// What the context asks of the engine.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Ask {
    pub seccomp: Seccomp,
    /// The lists of paths of the context are the lists of the container,
    /// empty ones too: they replace the defaults of the engine.
    pub own_paths: bool,
}

/// The request of the engine for a security context.  A privileged
/// container has no profile (the one named does not apply) and no paths;
/// a profile that is not named is none, as the API says of the deprecated
/// path (the kubelet names one always); no context at all is the engine's
/// defaults.
pub fn from_cri(c: &Context) -> Ask {
    let seccomp = if !c.present {
        Seccomp::Default
    } else if c.privileged {
        Seccomp::Unconfined
    } else {
        match c.seccomp {
            Profile::RuntimeDefault => Seccomp::Default,
            Profile::Localhost => Seccomp::Custom,
            Profile::Absent | Profile::Unconfined => Seccomp::Unconfined,
        }
    };
    let own_paths = if c.present { !c.privileged } else { false };
    Ask { seccomp, own_paths }
}
