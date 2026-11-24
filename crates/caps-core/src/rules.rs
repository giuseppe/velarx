// SPDX-License-Identifier: Apache-2.0
//! The rules of the sets of a process, checked on every answer of `sets`.
//! They are stated by what a request means, not by how `sets` computes, so
//! that a computation that is wrong in another way than the one it was
//! written for still fails one.
//!
//! What the rules say of the kernel: the sets of a process must have
//! `effective` within `permitted`, `ambient` within `permitted` and
//! `inheritable`, and the runtime cannot give a capability outside the
//! bounding set of the engine in any set.  What the code does on top: the
//! inheritable set is within the permitted one too (root has the ambient
//! capabilities as its inheritable set, another user has what it was given).

use super::*;

/// `a` is within `b`.
fn within(a: u64, b: u64) -> bool {
    a & !b == 0
}

/// Checks the answer of `sets` for a request; a rule that fails panics with
/// its words, and the request.
pub fn check(r: &Request, answer: Result<Sets, Refusal>) {
    let what = || format!("{r:?}: {answer:?}");

    // All of them added and all of them dropped is a contradiction.
    if !r.privileged && r.add_all && r.drop_all {
        assert_eq!(answer, Err(Refusal::AddAndDropAll), "{}", what());
        return;
    }

    // The engine cannot give what it has not: a refusal names exactly that,
    // and only a refusal does.
    let lacking_add = r.add & !r.bounding;
    let lacking_ambient = r.ambient & !r.bounding;
    if lacking_add != 0 {
        assert_eq!(answer, Err(Refusal::Add(lacking_add)), "{}", what());
        return;
    }
    if lacking_ambient != 0 {
        assert_eq!(answer, Err(Refusal::Ambient(lacking_ambient)), "{}", what());
        return;
    }
    let s = answer.unwrap_or_else(|e| panic!("refused for nothing ({e:?}): {r:?}"));
    let all = [
        s.bounding,
        s.effective,
        s.permitted,
        s.inheritable,
        s.ambient,
    ];

    // What the kernel needs, and the engine's bound.
    for set in all {
        assert!(
            within(set, r.bounding),
            "a set beyond the engine: {}",
            what()
        );
    }
    assert!(within(s.effective, s.permitted), "effective: {}", what());
    assert!(
        within(s.ambient, s.permitted),
        "ambient, permitted: {}",
        what()
    );
    assert!(
        within(s.ambient, s.inheritable),
        "ambient, inheritable: {}",
        what()
    );
    // What the code does on top.
    assert!(within(s.permitted, s.bounding), "permitted: {}", what());
    assert!(
        within(s.inheritable, s.permitted),
        "inheritable: {}",
        what()
    );

    // `--cap-drop` takes capabilities from every set, but not of a
    // privileged container.
    let dropped = if r.privileged { 0 } else { r.drop };
    for set in all {
        assert_eq!(set & dropped, 0, "a dropped capability: {}", what());
    }
    let asked = r.add & !dropped;
    let ambient = r.ambient & !dropped;
    let defaults = if r.drop_all {
        0
    } else {
        r.defaults & r.bounding & !dropped
    };

    // Nothing comes from elsewhere than the defaults, what was added and
    // the ambient capabilities, but for `--privileged` and `all`, which are
    // the engine's.
    let source = if r.privileged || r.add_all {
        r.bounding & !dropped
    } else {
        defaults | asked | ambient
    };
    for set in all {
        assert!(within(set, source), "from nowhere: {}", what());
    }

    // The bounding set has all that was asked for: the defaults (`--cap-drop
    // all` takes them), the added ones, the ambient ones, and for
    // `--privileged` and `all` everything of the engine that was not dropped.
    assert!(
        within(defaults | asked | ambient, s.bounding),
        "asked: {}",
        what()
    );
    if r.privileged {
        assert_eq!(s.bounding, r.bounding, "privileged: {}", what());
    }
    if r.add_all {
        assert!(within(r.bounding & !dropped, s.bounding), "all: {}", what());
    }

    if r.root {
        // Root has the bounding set, and the ambient capabilities (not the
        // others) are inherited.
        assert_eq!(s.effective, s.bounding, "root effective: {}", what());
        assert_eq!(s.permitted, s.bounding, "root permitted: {}", what());
        assert_eq!(s.inheritable, ambient, "root inheritable: {}", what());
        assert_eq!(s.ambient, ambient, "root ambient: {}", what());
    } else {
        // Another user has what was asked for by name (or all with `all`),
        // in every set but the bounding one.
        let named = if r.add_all { s.bounding } else { asked };
        for set in [s.effective, s.permitted, s.inheritable, s.ambient] {
            assert_eq!(set, named | ambient, "user: {}", what());
        }
    }
}
