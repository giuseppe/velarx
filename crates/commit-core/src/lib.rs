// SPDX-License-Identifier: Apache-2.0
//! The commit decision of a staged file: what a file must be shown to be
//! before it is given its name in the object store, and what the shell that
//! commits it (`velarx-content`, pull/commit.rs) may do with each answer.
//!
//! The claim the store makes is that a file is named only if (a) the kernel's
//! fs-verity measure of it is the digest it is named by, or (b) its bytes were
//! read and hashed to its key, or (c) it is the engine's own, or already
//! verified by the engine, or (d) for a kept object, the store already holds
//! it under that name.  With fs-verity required, nothing is named without a
//! kernel measure.  A refused file ([`Verdict::Wrong`]) always has
//! its staged name dropped; a hard error ([`Verdict::Fail`]) keeps it, so
//! that the caller may try again.
//!
//! The order of the I/O is fixed (measure, read or copy, measure the copy),
//! so there are two questions: [`plan`] says what the shell must do with the
//! file, [`verdict`] says what it is, from what the shell saw.  The core
//! compares the digests itself (the shell reports values, never "equal"),
//! and an object can be made only from a [`Named`], which only [`verdict`]
//! and [`keep`] make.
//!
//! What the core does not say: that the shell hashed the descriptor it then
//! links, the inode check of the link, the barriers, and that it drops the
//! name of a `Wrong` file.  A file of (c) with no kernel measure is named
//! unread, which is documented in THREAT-MODEL ("A store without fs-verity").
//!
//! Written to be translated (tools/verify): plain enums and structs, no
//! closure, no iterator adapter, one loop (`Dig::eq`).  That `plan`,
//! `verdict`, `keep` and `Dig::eq` answer for every input, and what they
//! answer, is proved in Lean (tools/verify/commit-core); the rules and the
//! walk of every input of a small world (`rules`, `walk`) check the same on
//! small cases.

/// A digest: the fs-verity digest of a file (`verity`) or the hash of its
/// content, of the algorithm `alg`; `len` of the 64 `bytes` are used.  The
/// shell makes them from the parsed digests; the core only compares them.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy)]
pub struct Dig {
    pub verity: bool,
    pub alg: u8,
    pub len: u8,
    pub bytes: [u8; 64],
}

/// Equal when they have the same kind, algorithm and the same `len` first
/// bytes (what is after them is not part of the digest).
impl PartialEq for Dig {
    fn eq(&self, other: &Self) -> bool {
        let mut same =
            self.verity == other.verity && self.alg == other.alg && self.len == other.len;
        let mut i = 0;
        while same && i < self.len as usize && i < 64 {
            same = self.bytes[i] == other.bytes[i];
            i += 1;
        }
        same
    }
}

impl Eq for Dig {}

/// What a staged file claims to be.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Claim {
    /// Its fs-verity digest is this one: the kernel's measure must be it
    Verity(Dig),
    /// The hash of its content is this key
    Content(Dig),
    /// The hash of its content is the key (first) and a replay proved the
    /// fs-verity digest it has (second): the measure must be that one, and
    /// then the content is not read again
    Replayed(Dig, Dig),
    /// The engine wrote it and proves it by other means: named by what the
    /// kernel measures, or by one read
    Engine,
    /// The engine, which a driver trusts to have read it, handed it over
    /// with this fs-verity digest
    Verified(Dig),
}

/// What is known before the file is opened.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub struct Facts {
    pub claim: Claim,
    /// The engine wrote the file itself, where no producer reaches it
    pub own: bool,
    /// The staging is on the store's file system: the inode can be linked
    pub same_fs: bool,
    /// fs-verity is required: nothing is named without a kernel measure
    pub required: bool,
}

/// Whether the store has the object a digest names, and whether the kernel
/// measures it as that digest (a file system with no fs-verity does not).
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Held {
    Lacks,
    Measures,
    Unmeasured,
}

/// Why a file is refused or the commit fails.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The fs-verity digest of a `Verity` claim is not the one measured or
    /// computed
    NotVerity,
    /// The same for a file the engine verified
    NotVerified,
    /// The same for a replay's digest
    NotReplayed,
    /// The fs-verity digest computed from the bytes is not the one the claim
    /// names
    NotKnown,
    /// The hash of the content is not the key
    NotContent,
    /// Fs-verity is required and the kernel measures nothing of the file
    NoMeasure,
    /// Fs-verity is required and the store has the object with no measure
    StoreUnmeasured,
    /// A digest the shell reported as an fs-verity one is not (a bug of
    /// the shell: nothing is named by it)
    NotFsVerity,
    /// A step the plan asked for was not done
    Unread,
    /// The shell did what the plan did not ask, or the plan names nothing
    NotPlanned,
}

/// What the shell must do with the file.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Plan {
    Wrong(Why),
    Fail(Why),
    /// The store has the object: read the content (`content`) and keep it
    Keep {
        content: bool,
    },
    /// Name it by what is known: the kernel's measure, or the claim of a
    /// verified file or of a replayed one that is the engine's own, unread
    Link,
    /// Read it once, and link its inode
    Read {
        content: bool,
        merkle: bool,
    },
    /// Copy it (its inode cannot be linked), hashing as it is copied
    Copy {
        content: bool,
    },
}

/// What the shell saw.  A step that was not done is a `None`.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy)]
pub struct Seen {
    /// The kernel's measure of the staged file, after fs-verity was enabled
    pub kernel: Option<Dig>,
    /// The fs-verity digest of the bytes of the read or of the copy
    pub merkle: Option<Dig>,
    /// The hash of the bytes of the read or of the copy
    pub content: Option<Dig>,
    /// The kernel's measure of the copy
    pub copy_kernel: Option<Dig>,
    /// The store, for the object [`plan`] was asked about
    pub held: Held,
}

/// What made a digest the name of a file.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// The kernel measures it
    Kernel,
    /// Its bytes were read
    Read,
    /// Its bytes were copied
    Copy,
    /// The engine's own, or verified by the engine
    Trusted,
    /// The store has it
    Store,
}

/// The digest a file may be named by, with the proof: made only by
/// [`verdict`] and [`keep`].
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub struct Named {
    verity: Dig,
    checked: bool,
    proof: Proof,
}

impl Named {
    /// The fs-verity digest of the object
    pub fn verity(&self) -> Dig {
        self.verity
    }

    /// The kernel measures the object as that digest
    pub fn checked(&self) -> bool {
        self.checked
    }

    pub fn proof(&self) -> Proof {
        self.proof
    }
}

/// What the file is.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Verdict {
    /// Link it by this name (the store does not have it)
    Name(Named),
    /// The store has it: drop the staged name
    Keep(Named),
    /// It is not what it claims: drop the staged name, it is refused
    Wrong(Why),
    /// The commit fails, the staged name stays
    Fail(Why),
}

/// What the claim expects of a digest of the file's fs-verity, if anything.
fn expected(claim: &Claim) -> Option<(Dig, Why)> {
    match claim {
        Claim::Verity(v) => Some((*v, Why::NotVerity)),
        Claim::Verified(v) => Some((*v, Why::NotVerified)),
        Claim::Replayed(_, r) => Some((*r, Why::NotReplayed)),
        Claim::Content(_) | Claim::Engine => None,
    }
}

/// The key of the content a claim has, if any.
fn key_of(claim: &Claim) -> Option<Dig> {
    match claim {
        Claim::Content(k) | Claim::Replayed(k, _) => Some(*k),
        Claim::Verity(_) | Claim::Verified(_) | Claim::Engine => None,
    }
}

/// A claim whose fs-verity digest is not one (a content hash in its place):
/// it can never be met.
fn malformed(claim: &Claim) -> Option<Why> {
    match expected(claim) {
        Some((e, why)) if !e.verity => Some(why),
        _ => None,
    }
}

/// A digest of the fs-verity of the file that is not the one expected: the
/// kernel's measure, or (`computed`) one made from the bytes.
fn differs(claim: &Claim, d: Option<Dig>, computed: bool) -> Option<Why> {
    match (expected(claim), d) {
        (Some((e, why)), Some(d)) if e != d => Some(if computed { Why::NotKnown } else { why }),
        _ => None,
    }
}

/// Both are there and not the same digest.
fn disagree(a: Option<Dig>, b: Option<Dig>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

/// What the shell reported that is not what the claim says: the kernel's
/// measure and the digest of a read or a copy against the claimed fs-verity
/// digest and against each other, the content hash against the key.
fn reported(f: &Facts, seen: &Seen) -> Option<Why> {
    if let Some(why) = malformed(&f.claim) {
        return Some(why);
    }
    if let Some(why) = differs(&f.claim, seen.kernel, false) {
        return Some(why);
    }
    if let Some(why) = differs(&f.claim, seen.merkle, true) {
        return Some(why);
    }
    // (the kernel measured a file nothing can change, so the digest of the
    // bytes read from it is that measure: if not, the read is wrong)
    if disagree(seen.kernel, seen.merkle) {
        return Some(Why::NotKnown);
    }
    // (the kernel measured the copy only the engine wrote: if its measure is
    // not the digest of the bytes written, the copy is wrong)
    if disagree(seen.copy_kernel, seen.merkle) {
        return Some(Why::NotKnown);
    }
    match (key_of(&f.claim), seen.content) {
        (Some(k), Some(c)) if k != c => Some(Why::NotContent),
        _ => None,
    }
}

/// The digest of the kernel's measure, or of a read or a copy, is an
/// fs-verity digest if there is one.
fn is_fs_verity(d: Option<Dig>) -> bool {
    match d {
        Some(d) => d.verity,
        None => true,
    }
}

/// What the shell reports as fs-verity digests (the kernel's measure and the
/// digests computed from the bytes) are: the types do not say it, and a
/// content hash there would be named as one.
fn reports_fs_verity(seen: &Seen) -> bool {
    is_fs_verity(seen.kernel) && is_fs_verity(seen.merkle) && is_fs_verity(seen.copy_kernel)
}

/// Both are there and the same digest.
fn measured_as(a: Option<Dig>, b: Option<Dig>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Whether the bytes are read to be compared with the key: a content claim,
/// and a replayed one the kernel's measure does not prove.
fn reads_content(claim: &Claim, kernel: Option<Dig>) -> bool {
    match claim {
        Claim::Content(_) => true,
        Claim::Replayed(_, r) => !measured_as(kernel, Some(*r)),
        Claim::Verity(_) | Claim::Verified(_) | Claim::Engine => false,
    }
}

/// The digest of the object the store is asked about: the kernel's measure,
/// else the digest a verity claim names.
fn asked(claim: &Claim, kernel: Option<Dig>) -> Option<Dig> {
    match (kernel, claim) {
        (Some(m), _) => Some(m),
        (None, Claim::Verity(v)) => Some(*v),
        _ => None,
    }
}

/// What the shell must do with a file, from what is known before it reads
/// anything: the kernel's measure of it (none where the file system has no
/// fs-verity), and whether the store has the object `held` is about (the
/// kernel's measure, or for a verity claim the digest it names before the
/// file is opened; `Lacks` where there is none).
pub fn plan(f: &Facts, kernel: Option<Dig>, held: Held) -> Plan {
    if let Some(why) = malformed(&f.claim) {
        return Plan::Wrong(why);
    }
    if let Some(why) = differs(&f.claim, kernel, false) {
        return Plan::Wrong(why);
    }
    let content = reads_content(&f.claim, kernel);
    if asked(&f.claim, kernel).is_some() && held != Held::Lacks {
        if f.required && held == Held::Unmeasured {
            return Plan::Fail(Why::StoreUnmeasured);
        }
        return Plan::Keep { content };
    }
    if kernel.is_none() && f.required && f.same_fs {
        return Plan::Fail(Why::NoMeasure);
    }
    if !f.same_fs {
        return Plan::Copy { content };
    }
    match (kernel, f.claim) {
        (Some(_), _) if content => Plan::Read {
            content,
            merkle: false,
        },
        (Some(_), _) => Plan::Link,
        // (nothing reads these: a verified file, and a replayed one that is
        // the engine's own, are named by their claim; a replayed file of
        // another producer is read and compared like any other)
        (None, Claim::Verified(_)) => Plan::Link,
        (None, Claim::Replayed(_, _)) if f.own => Plan::Link,
        (None, _) => Plan::Read {
            content,
            merkle: true,
        },
    }
}

/// The key must be what was hashed, when the plan asked for the hash.
fn content_checked(f: &Facts, content: bool, seen: &Seen) -> Option<Verdict> {
    match (content, seen.content) {
        (false, _) => None,
        (true, None) => Some(Verdict::Fail(Why::Unread)),
        (true, Some(c)) => match key_of(&f.claim) {
            Some(k) if k == c => None,
            Some(_) => Some(Verdict::Wrong(Why::NotContent)),
            None => Some(Verdict::Fail(Why::NotPlanned)),
        },
    }
}

/// The name a file is given by a digest computed by a read or a copy.
fn computed(f: &Facts, proof: Proof, d: Option<Dig>, checked: bool) -> Verdict {
    match d {
        None => Verdict::Fail(Why::Unread),
        Some(d) => {
            let proof = match f.claim {
                Claim::Engine => Proof::Trusted,
                _ => proof,
            };
            Verdict::Name(Named {
                verity: d,
                checked,
                proof,
            })
        }
    }
}

/// What the file is, from what the shell saw while it did what [`plan`]
/// said (the plan is made again from `seen`: the shell cannot pass another).
/// A digest that is not the one expected is `Wrong`; a step that was asked
/// for and not done, or fs-verity required and no kernel measure, `Fail`.
pub fn verdict(f: &Facts, seen: &Seen) -> Verdict {
    if let Some(why) = reported(f, seen) {
        return Verdict::Wrong(why);
    }
    if !reports_fs_verity(seen) {
        return Verdict::Fail(Why::NotFsVerity);
    }
    match plan(f, seen.kernel, seen.held) {
        Plan::Wrong(why) => Verdict::Wrong(why),
        Plan::Fail(why) => Verdict::Fail(why),
        Plan::Keep { content } => match (
            content_checked(f, content, seen),
            asked(&f.claim, seen.kernel),
        ) {
            (Some(v), _) => v,
            (None, None) => Verdict::Fail(Why::NotPlanned),
            (None, Some(d)) => {
                let proof = match seen.kernel {
                    Some(_) => Proof::Kernel,
                    None => Proof::Store,
                };
                Verdict::Keep(Named {
                    verity: d,
                    checked: seen.held == Held::Measures,
                    proof,
                })
            }
        },
        Plan::Link => match (seen.kernel, f.claim) {
            (Some(m), _) => Verdict::Name(Named {
                verity: m,
                checked: true,
                proof: Proof::Kernel,
            }),
            (None, Claim::Verified(d)) | (None, Claim::Replayed(_, d)) => Verdict::Name(Named {
                verity: d,
                checked: false,
                proof: Proof::Trusted,
            }),
            _ => Verdict::Fail(Why::NotPlanned),
        },
        Plan::Read { content, merkle } => match (content_checked(f, content, seen), seen.kernel) {
            (Some(v), _) => v,
            (None, Some(m)) => Verdict::Name(Named {
                verity: m,
                checked: true,
                proof: Proof::Kernel,
            }),
            (None, None) if merkle => computed(f, Proof::Read, seen.merkle, false),
            (None, None) => Verdict::Fail(Why::NotPlanned),
        },
        Plan::Copy { content } => match content_checked(f, content, seen) {
            Some(v) => v,
            None => {
                let checked = measured_as(seen.copy_kernel, seen.merkle);
                if f.required && !checked {
                    Verdict::Fail(Why::NoMeasure)
                } else {
                    computed(f, Proof::Copy, seen.merkle, checked)
                }
            }
        },
    }
}

/// The store has the object `named` names, though it was not asked before
/// (the digest came from a read or a copy): the staged name is dropped.  An
/// object of the store that the kernel does not measure is kept as it is,
/// unchecked, unless fs-verity is required: that fails.
pub fn keep(f: &Facts, named: Named, held: Held) -> Verdict {
    match held {
        Held::Lacks => Verdict::Name(named),
        Held::Unmeasured if f.required => Verdict::Fail(Why::StoreUnmeasured),
        Held::Measures | Held::Unmeasured => Verdict::Keep(Named {
            checked: held == Held::Measures,
            proof: Proof::Store,
            ..named
        }),
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
