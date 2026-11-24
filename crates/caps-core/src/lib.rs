// SPDX-License-Identifier: Apache-2.0
//! The capability sets of a container process, as podman gives them: from
//! what the request asks (`--privileged`, `--cap-add`, `--cap-drop`, the
//! ambient capabilities of the CRI, the user) and what the engine can give
//! (its bounding set), the five sets of the process, or a refusal.
//!
//! A set of capabilities is a `u64`: bit n is capability n of the kernel.
//! What stays in the shell: the names, `all` as a word (it comes as a flag),
//! the bounding set of the engine, and the OCI types.
//!
//! Written to be translated (tools/verify): plain integers, no loop, no
//! closure, no iterator adapter.  That `sets` returns for every request, and
//! what it returns, is proved in Lean (tools/verify/caps-core).

/// What a container asks for, and what the engine has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The bounding set of the engine: the capabilities it can give.
    pub bounding: u64,
    /// The capabilities of a container that asks for nothing.
    pub defaults: u64,
    /// `--privileged`: everything the engine has, and `drop` does not apply.
    pub privileged: bool,
    /// The user of the process is root (uid 0 in the container).
    pub root: bool,
    /// `--cap-add`, by name; `add_all` is `--cap-add all`.
    pub add: u64,
    pub add_all: bool,
    /// `--cap-drop`, by name; `drop_all` is `--cap-drop all`, which takes
    /// the defaults away and nothing else.
    pub drop: u64,
    pub drop_all: bool,
    /// The ambient capabilities of the CRI: asked for by name, and in every
    /// set of the process, root or not.
    pub ambient: u64,
}

/// The five sets of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sets {
    pub bounding: u64,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub ambient: u64,
}

/// A request the engine cannot satisfy, with the capabilities it lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `--cap-add all` with `--cap-drop all`, which contradict each other
    /// (podman refuses it too); `--privileged` has no `drop`.
    AddAndDropAll,
    /// `--cap-add` names capabilities outside the bounding set of the engine.
    Add(u64),
    /// An ambient capability is outside the bounding set of the engine.
    Ambient(u64),
}

/// The sets of the process for a request.
///
/// The bounding set is the defaults the engine has (all of the engine's for
/// `--privileged` and `add_all`, none for `drop_all`; a default the engine
/// lacks is left out without a word, an added one is refused) plus `add`,
/// minus `drop` (not for `--privileged`), plus the ambient capabilities that
/// `drop` did not take.
/// Root has it as its effective and permitted set, and the ambient
/// capabilities as its inheritable and ambient sets (CVE-2022-27651).  Another
/// user has only what was asked for, in each of the four sets: `add` (all of
/// the bounding set for `add_all`) and the ambient capabilities.
pub fn sets(r: &Request) -> Result<Sets, Refusal> {
    if !r.privileged && r.add_all && r.drop_all {
        return Err(Refusal::AddAndDropAll);
    }
    if r.add & !r.bounding != 0 {
        return Err(Refusal::Add(r.add & !r.bounding));
    }
    if r.ambient & !r.bounding != 0 {
        return Err(Refusal::Ambient(r.ambient & !r.bounding));
    }
    let mut caps = if r.privileged || r.add_all {
        r.bounding
    } else if r.drop_all {
        0
    } else {
        r.defaults & r.bounding
    };
    caps |= r.add;
    let mut ambient = r.ambient;
    if !r.privileged {
        caps &= !r.drop;
        ambient &= !r.drop;
    }
    caps |= ambient;
    if r.root {
        return Ok(Sets {
            bounding: caps,
            effective: caps,
            permitted: caps,
            inheritable: ambient,
            ambient,
        });
    }
    let mut given = if r.add_all { caps } else { caps & r.add };
    given |= ambient;
    Ok(Sets {
        bounding: caps,
        effective: given,
        permitted: given,
        inheritable: given,
        ambient: given,
    })
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
