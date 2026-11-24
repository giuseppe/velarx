// SPDX-License-Identifier: Apache-2.0
//! The rules of the commit decision, checked on every answer of `plan` and
//! `verdict`.  They are stated by what the store promises (a file is named
//! only on evidence), not by how `verdict` computes, so that a computation
//! that is wrong in another way than the one it was written for still fails
//! one.
//!
//! The evidence of a name `d` is (a) the kernel's measure is `d`, (b) the
//! bytes were read or copied and hashed to `d` (and to the key where the
//! claim is a content hash), or (c) the file is the engine's own, or the
//! engine verified it.
//!
//! 1. A name has evidence, the one its proof says.
//! 2. Fs-verity required: a name has a kernel measure of `d` (of the copy
//!    where it was copied); a file kept has one of the staged file or of the
//!    store's object.
//! 3. A content claim is named or kept only with the hash of its content
//!    equal to the key; a replayed claim of a file that is not the engine's
//!    only with that, or the kernel's measure equal to the replay's.
//! 4. A digest reported that is not the one the claim expects, or a kernel
//!    measure and a computed digest that are not one, is `Wrong`,
//!    and `Wrong` is given for nothing else.
//! 5. `Fail` names nothing (by its type); it is given for a measure that is
//!    required and missing, or a step that was not done, never for a
//!    consistent file.
//! 6. What is named is an fs-verity digest, never a content hash; the plan
//!    never copies on the store's file system, and never links or reads
//!    off it.
//! 7. A store that has the object is never linked over: kept, or refused.
//! 8. A file that is consistent and has its evidence is named (the rules
//!    above would pass a commit that refuses everything).
//! 9. The plan names unread only the engine's own replayed files and the
//!    verified ones; every other file is measured, read or copied.
//! 10. A report of the kernel's measure or of a computed digest that is not
//!     an fs-verity digest is never named or kept: the answer is `Fail`
//!     (unless a digest already disagrees with the claim: `Wrong`).

use super::*;

/// What the claim expects of the file's fs-verity digest, by its words.
fn verity_of(claim: &Claim) -> Option<Dig> {
    match claim {
        Claim::Verity(v) | Claim::Verified(v) | Claim::Replayed(_, v) => Some(*v),
        Claim::Content(_) | Claim::Engine => None,
    }
}

/// The key of the content of the claim.
fn key(claim: &Claim) -> Option<Dig> {
    match claim {
        Claim::Content(k) | Claim::Replayed(k, _) => Some(*k),
        _ => None,
    }
}

/// The engine's own file that a replay read, or one it verified: named
/// without a read.
fn trusted(f: &Facts, d: Dig) -> bool {
    match f.claim {
        Claim::Verified(v) => v == d,
        Claim::Replayed(_, r) => f.own && r == d,
        _ => false,
    }
}

/// Whether the content of a claim has to have been hashed to the key:
/// all of a content claim; a replayed one that the kernel does not prove.
fn needs_content(f: &Facts, kernel: Option<Dig>) -> bool {
    match f.claim {
        Claim::Content(_) => true,
        Claim::Replayed(_, r) => kernel != Some(r),
        _ => false,
    }
}

/// The digest the store is asked about.
fn asked(f: &Facts, kernel: Option<Dig>) -> Option<Dig> {
    match (kernel, f.claim) {
        (Some(m), _) => Some(m),
        (None, Claim::Verity(v)) => Some(v),
        _ => None,
    }
}

/// Checks the plan of the facts; a rule that fails panics with its words.
pub fn check_plan(f: &Facts, kernel: Option<Dig>, held: Held, p: Plan) {
    let what = || format!("{f:?} {kernel:?} {held:?}: {p:?}");
    // 6
    match p {
        Plan::Copy { .. } => assert!(!f.same_fs, "copy of a linkable file: {}", what()),
        Plan::Link | Plan::Read { .. } => {
            assert!(f.same_fs, "link of a file of another fs: {}", what())
        }
        _ => {}
    }
    // 9: unread names
    if p == Plan::Link {
        assert!(
            kernel.is_some() && !needs_content(f, kernel)
                || matches!(f.claim, Claim::Verified(_))
                || matches!(f.claim, Claim::Replayed(..)) && f.own,
            "named unread: {}",
            what()
        );
    }
    // 7
    if asked(f, kernel).is_some() && held != Held::Lacks {
        let keeps = matches!(p, Plan::Keep { .. } | Plan::Wrong(_))
            || p == Plan::Fail(Why::StoreUnmeasured) && f.required && held == Held::Unmeasured;
        assert!(keeps, "the store has it: {}", what());
    }
}

/// Checks the answer of `verdict` for the facts and what was seen; a rule
/// that fails panics with its words.
pub fn check(f: &Facts, seen: &Seen, v: Verdict) {
    let what = || format!("{f:?} {seen:?}: {v:?}");

    // 4: what is reported against what the claim expects
    let mut mismatch = false;
    for d in [seen.kernel, seen.merkle] {
        mismatch |= matches!((verity_of(&f.claim), d), (Some(e), Some(d)) if e != d);
    }
    mismatch |= matches!((key(&f.claim), seen.content), (Some(k), Some(c)) if k != c);
    // (the measure and the digest of the bytes of one file are one)
    mismatch |= matches!((seen.kernel, seen.merkle), (Some(k), Some(m)) if k != m);
    // (and the measure of the copy and the digest of the bytes written)
    mismatch |= matches!((seen.copy_kernel, seen.merkle), (Some(k), Some(m)) if k != m);
    // (a claim that names a content hash as its fs-verity digest)
    mismatch |= matches!(verity_of(&f.claim), Some(e) if !e.verity);
    assert_eq!(
        matches!(v, Verdict::Wrong(_)),
        mismatch,
        "wrong: {}",
        what()
    );

    // 10
    let bad_report = [seen.kernel, seen.merkle, seen.copy_kernel]
        .iter()
        .any(|d| matches!(d, Some(d) if !d.verity));
    if !mismatch && bad_report {
        assert_eq!(v, Verdict::Fail(Why::NotFsVerity), "bad report: {}", what());
    }

    // 5
    if let Verdict::Fail(why) = v {
        assert!(
            why != Why::NotFsVerity || bad_report,
            "a report that is fine: {}",
            what()
        );
        assert!(!mismatch, "fail of a wrong file: {}", what());
        assert!(
            why != Why::NotPlanned,
            "an answer the plan cannot give: {}",
            what()
        );
        if matches!(why, Why::NoMeasure | Why::StoreUnmeasured) {
            assert!(f.required, "fail without the requirement: {}", what());
        }
        // (the store's object is not measured: fs-verity required)
        if f.required
            && !bad_report
            && seen.held == Held::Unmeasured
            && asked(f, seen.kernel).is_some()
        {
            assert_eq!(v, Verdict::Fail(Why::StoreUnmeasured), "{}", what());
        }
    }

    if !mismatch && !bad_report {
        if let Some((d, checked)) = accepted(f, seen) {
            assert!(
                matches!(v, Verdict::Name(n) if n.verity() == d && n.checked() == checked),
                "a file with its evidence is not named: {}",
                what()
            );
        }
    }

    let (n, kept) = match v {
        Verdict::Name(n) => (n, false),
        Verdict::Keep(n) => (n, true),
        Verdict::Wrong(_) | Verdict::Fail(_) => return,
    };
    let d = n.verity();

    // 6
    assert!(
        d.verity,
        "a name that is not an fs-verity digest: {}",
        what()
    );

    // 1
    match n.proof() {
        Proof::Kernel => assert_eq!(seen.kernel, Some(d), "kernel: {}", what()),
        Proof::Read | Proof::Copy => assert_eq!(seen.merkle, Some(d), "read: {}", what()),
        Proof::Trusted => assert!(
            trusted(f, d) && seen.kernel.is_none()
                || f.claim == Claim::Engine && seen.merkle == Some(d),
            "trusted: {}",
            what()
        ),
        Proof::Store => assert!(
            seen.held != Held::Lacks && f.claim == Claim::Verity(d) && seen.kernel.is_none(),
            "store: {}",
            what()
        ),
    }
    // (an object kept is checked when the store's file is measured, and a
    // name is checked when the kernel measured the file or its copy)
    if kept {
        assert_eq!(n.checked(), seen.held == Held::Measures, "{}", what());
    } else {
        assert_eq!(
            n.checked(),
            if f.same_fs {
                seen.kernel == Some(d)
            } else {
                seen.copy_kernel == Some(d) && seen.merkle == Some(d)
            },
            "checked: {}",
            what()
        );
    }

    // 2
    if f.required {
        if kept {
            assert!(
                seen.held == Held::Measures,
                "kept without a measure: {}",
                what()
            );
        } else {
            assert!(
                seen.kernel == Some(d) || seen.copy_kernel == Some(d),
                "named without a measure: {}",
                what()
            );
            assert!(n.checked(), "required and not checked: {}", what());
        }
    }

    // 3
    if let Claim::Content(k) = f.claim {
        assert_eq!(seen.content, Some(k), "content: {}", what());
    }

    // (a replayed file of another producer was measured, or read to the key)
    if let Claim::Replayed(k, r) = f.claim {
        if !f.own {
            assert!(
                seen.kernel == Some(r) || seen.content == Some(k),
                "replayed: {}",
                what()
            );
        }
    }

    // 7
    if asked(f, seen.kernel).is_some() && seen.held != Held::Lacks {
        assert!(kept, "linked over the store's: {}", what());
    }
}

/// 8: the name a consistent file with its evidence is given, if any.
fn accepted(f: &Facts, seen: &Seen) -> Option<(Dig, bool)> {
    if seen.held != Held::Lacks {
        return None;
    }
    let content_ok = !needs_content(f, seen.kernel) || seen.content == key(&f.claim);
    match (f.same_fs, seen.kernel, seen.merkle) {
        (true, Some(m), _) if content_ok => Some((m, true)),
        (false, _, Some(d)) if content_ok && seen.copy_kernel == Some(d) => Some((d, true)),
        (true, None, _) if !f.required => match f.claim {
            Claim::Verified(d) => Some((d, false)),
            Claim::Replayed(_, r) if f.own => Some((r, false)),
            _ => seen.merkle.filter(|_| content_ok).map(|d| (d, false)),
        },
        _ => None,
    }
}

/// Checks `keep`: the store that has the object the file was named by keeps
/// it, whatever the file was, and a store that lacks it is linked.
pub fn check_keep(f: &Facts, n: Named, held: Held, v: Verdict) {
    let what = || format!("{f:?} {n:?} {held:?}: {v:?}");
    match (held, v) {
        (Held::Lacks, Verdict::Name(m)) => assert_eq!(m, n, "{}", what()),
        (Held::Unmeasured, Verdict::Fail(Why::StoreUnmeasured)) if f.required => {}
        (Held::Measures | Held::Unmeasured, Verdict::Keep(m))
            if !f.required || held == Held::Measures =>
        {
            assert_eq!(m.verity(), n.verity(), "{}", what());
            assert_eq!(m.checked(), held == Held::Measures, "{}", what());
            assert_eq!(m.proof(), Proof::Store, "{}", what());
        }
        _ => panic!("{}", what()),
    }
}
