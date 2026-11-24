-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/commit-core, the decision that gives a staged
-- file a name in the object store, in words and in statements, with no proof.  This file is
-- what a reviewer reads; Lean checks the rest (the proofs are in the other files of CommitCore/).
--
-- The decision has four functions.  `plan` says, before the shell reads anything, what it must do
-- with the file (link it, read it, copy it, keep the store's object, or stop).  `verdict` says
-- what the file is, from what the shell saw while it did that: NAMED (link it under this digest),
-- KEPT (the store has it, drop the staged name), REFUSED (`Wrong`: it is not what it claims) or a
-- FAILURE (`Fail`: a step is missing, the commit stops).  `keep` is asked again when a digest
-- comes from reading or copying the bytes: does the store have it already?  `Dig::eq` is how
-- digests are compared.  The shell is `prepare_one` of crates/content/src/pull/commit.rs.
--
-- Why it is needed: this is the integrity claim of the store: a file gets the name of its
-- fs-verity digest only on evidence that its bytes are those of the digest.  The tests of the
-- crate (src/walk.rs, src/rules.rs) check ten rules on every input of a small world (three
-- digests, one length).  Each claim below is a rule for EVERY input, with digests of any
-- algorithm and length, any claim, any facts and any report of the shell.  A proof is worth
-- what its statement says, so each claim has a comment of what it claims and of what it
-- does NOT.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no loop that does not
-- end), and that its answer is as stated.
--
-- Upper and lower bounds: "a file is named only on evidence" alone is satisfied by a core that
-- refuses everything.  So the claims come in two kinds: what is NEVER named or kept
-- (NamedImpliesEvidence, ReplayedByAnotherProducerIsNeverTrusted, RequiredMeansMeasured, ...)
-- and what is ALWAYS named when the honest evidence is seen (AMeasuredFileIsNamed,
-- AReadFileIsNamed, ACopiedFileIsNamed, AFileTheEngineVouchesForIsNamed, AKnownObjectIsKept;
-- each assumes an honest shell: nothing it reported disagrees with the claim (`Mismatch`), and
-- its digests are fs-verity ones (`ReportsAreFsVerity`)).
--
-- Read before this file: lib.rs and rules.rs of crates/commit-core.
--
-- The vocabulary, in one place.
--   claim        what the file says it is: `Verity d` (its fs-verity digest is `d`), `Content k`
--                (the hash of its content is `k`), `Replayed k r` (the hash of its content is `k`
--                and a replay proved its fs-verity digest `r`), `Engine` (the engine wrote it),
--                `Verified d` (the engine read it and says its fs-verity digest is `d`).
--   facts        the claim, `own` (the engine wrote the file itself), `same_fs` (the staging is on
--                the store's file system: the inode can be linked), `required` (fs-verity is
--                required).
--   seen         what the shell saw: `kernel` (the kernel's fs-verity measure of the staged file),
--                `merkle` (the fs-verity digest computed from the bytes it read or copied),
--                `content` (the hash of the bytes it read or copied), `copy_kernel` (the kernel's
--                measure of the copy), `held` (whether the store has the object: `Lacks`,
--                `Measures` (the kernel measures it as its name), `Unmeasured`).  A step that
--                was not done is `none`.
--
-- Index.  What each claim is about, what is trusted and what is not claimed:
--
--   Claimed (each for every input; the function returns, and):
--
--   The functions and the digests
--     NothingEverPanics                 `Dig::eq`, `plan`, `verdict` and `keep` always return
--     DigestEqualityIsSameDigest        `Dig::eq` is true exactly when kind, algorithm, length
--                                       and the first `len` bytes agree
--     SameDigestIsAnEquality            `Same` is reflexive, symmetric and transitive
--
--   Never named or kept without evidence
--     NamedImpliesEvidence              named or kept under `d`: the kernel measured `d`, or
--                                       the bytes were read and hash to `d` (and to the key),
--                                       or the engine vouches (the trusted cases, said
--                                       plainly), or the store already holds it
--     ReplayedByAnotherProducerIsNeverTrusted
--                                       a replay that is not the engine's own is never named
--                                       unread: the kernel measured it or the bytes were read
--     NoNameAgainstTheMeasure           a name is never given against a kernel measure (of
--                                       the file or of its copy) that disagrees with the
--                                       bytes read or written
--     ANameIsAnFsVerityDigest           what is named or kept is an fs-verity digest, the one
--                                       the claim names if it names one, whatever the shell
--                                       reports (a content hash there is `NotFsVerity`)
--     WrongExactlyWhenADigestDisagrees  a refusal exactly when a digest seen is not the one
--                                       the claim expects, or the kernel's measure (of the
--                                       file or of its copy) is not the digest of the bytes
--                                       (or the claim cannot be met)
--     AFailureHasItsReason              `Fail` is never "not planned", and "no measure" needs
--                                       fs-verity required
--
--   Fs-verity required, and the store
--     RequiredMeansMeasured             required: what is named has a kernel measure equal to
--                                       its name (of the file, or of its copy), what is kept
--                                       is measured in the store
--     CheckedMeansTheKernelMeasured     the flag `checked` of an answer is true exactly when
--                                       the kernel measured the file (or its copy, or the
--                                       store's object) as the name
--     AnUnmeasuredObjectIsNeverKeptWhenRequired
--                                       required, and the store's object not measured: the
--                                       answer is a failure (or a refusal), not a name
--     AStoreObjectIsNeverLinkedOver     the store has the object: the answer is not a name
--     KeepNeverNamesWhatItWasNotGiven   `keep` answers with the name it was given, or keeps the
--                                       store's object, and never links over it
--     KeepNeedsAMeasureWhenRequired     `keep`, required: a store object with no measure fails
--     AKernelProofMeansTheStoreWasAsked the proof `Kernel` is exactly the kernel's evidence, and
--                                       the store was asked about that very name (the shell
--                                       skips `keep` for it)
--
--   The plan
--     TheVerdictIsForThePlan            `verdict` names only what `plan` asked, and only when
--                                       everything the plan asked was seen
--     ThePlanFitsTheFileSystem          `plan` copies only off the store's file system, links
--                                       and reads only on it
--     OnlyTrustedFilesAreLinkedUnread   `plan` links a file with no read only when the kernel
--                                       measures it, or the engine vouches for it
--
--   Always named when the honest evidence is seen (so refusing everything fails)
--     AMeasuredFileIsNamed, AReadFileIsNamed, ACopiedFileIsNamed,
--     AFileTheEngineVouchesForIsNamed, AKnownObjectIsKept
--
--   The ten rules of rules.rs, and where each is claimed:
--     1 a name has the evidence its proof says    NamedImpliesEvidence (the evidence);
--                                                 AKernelProofMeansTheStoreWasAsked and
--                                                 KeepNeverNamesWhatItWasNotGiven (the proofs
--                                                 `Kernel` and `Store`, which the shell reads)
--     2 required: a name has a kernel measure     RequiredMeansMeasured
--     3 a content claim is named with its key     NamedImpliesEvidence (`KeyIsRead`),
--                                                 ReplayedByAnotherProducerIsNeverTrusted
--     4 `Wrong` exactly for a digest that differs WrongExactlyWhenADigestDisagrees
--     5 `Fail` names nothing, has its reason      AFailureHasItsReason, TheVerdictIsForThePlan
--     6 an fs-verity digest; the plan fits        ANameIsAnFsVerityDigest, ThePlanFitsTheFileSystem
--     7 the store's object is never linked over   AStoreObjectIsNeverLinkedOver, KeepNever...
--     8 the honest file is named                  the five claims "is named" and "is kept"
--     9 unread names are the engine's             OnlyTrustedFilesAreLinkedUnread
--     10 a report that is not fs-verity is never named  ANameIsAnFsVerityDigest
--
--   Of the rules, not claimed: the proofs `Read`, `Copy` and `Trusted` of a name say which
--   evidence it has (the shell does not read them, only whether the proof is `Kernel`);
--   that `Fail` is never given for a file that agrees with its claim in every case (the five
--   liveness claims say it for the cases they state; for the others, `TheVerdictIsForThePlan`
--   says that a file is never named with less than the plan asked); which `Why` a refusal
--   carries; and the walk's counts (that every kind of answer is given): the liveness
--   claims say that the answers are given.
--
--   Trusted: Charon and Aeneas (../../pins) and nothing else: no model of the standard library is
--   written by hand, and no function of it is assumed (the run prints none).
--
--   Not claimed:
--   - that the shell observes truthfully: that the measure is of the inode it then links,
--     and the hash is of the bytes it read (the claims are about what it REPORTS in `seen`);
--   - that it reports `held` truthfully for the digest it was asked about, and that nothing
--     changes the store between that question and the link (no race);
--   - that a kernel measure that fails to parse is reported as `none` (the shell does it:
--     `dig_of`), and that the shell's measure, hasher and `dig_of` always give fs-verity
--     digests: this is what makes `NotFsVerity` change nothing in production;
--   - that it does the I/O the plan says and acts on the verdict (that it links a `Name`, drops
--     the name of a `Wrong`, calls `keep` after a read, does not link over the store's file);
--   - that the facts are true: `own`, `required`, `same_fs`, and the claim itself (a `Verified`
--     digest is the engine's word, an own `Replayed` one too: said in `TrustedEvidence`);
--   - that an object can be made only from a `Named` (the Rust privacy of its fields, and that no
--     other code makes the store's object type);
--   - that a hash is collision resistant (digests the same are taken as the same bytes);
--   - that fs-verity of the kernel is right;
--   - that the staged file of a `Verity` claim whose object the store has is the object: it is
--     dropped unread, the store's object is what stays (`TheStoreHoldsIt`); the store's existing
--     contents are not re-examined here (that is `velarx check`'s job), and with fs-verity
--     required this case is an error unless the kernel measures the store's object.
--
-- Notation:
--   - `verdict f seen ⦃ v => P v ⦄` reads: the Rust function `verdict`, given `f` and `seen`,
--     returns (it does not panic) and its answer `v` satisfies `P v`.  `v = .Name n` is "the
--     answer is `Name n`": link the file under `n.verity`; `.Keep n` is "the store has it";
--     `.Wrong why` is "refused" and `.Fail why` "the commit fails".
--   - `d.verity` is the flag of a digest `d` that says it is an fs-verity digest (not the hash of
--     a content); `d.alg` and `d.len` its algorithm and length.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and",
--     `∨` is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `≠` is "is not".
--   - `seen.kernel = some m` is "the kernel measured the file, as `m`"; `none` is "it did not".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_commit_core

namespace CommitCore

/-! ### Digests -/

/-- Two digests are the same: they have the same kind (fs-verity digest or hash of a content),
the same algorithm, the same length, and the same bytes as far as that length goes (what is
after the `len` first bytes of the 64 is not part of the digest). -/
def Same (a b : Dig) : Prop :=
  a.verity = b.verity ∧ a.alg = b.alg ∧ a.len = b.len ∧
  ∀ i : Nat, i < a.len.val → a.bytes.val[i]? = b.bytes.val[i]?

/-- The fs-verity digest a claim says the file has, if it says one: a `Verity`, a `Verified`
and a `Replayed` claim do; a `Content` and an `Engine` claim leave the name to the kernel's
measure. -/
def claimedVerity : Claim → Option Dig
  | .Verity v => some v
  | .Verified v => some v
  | .Replayed _ r => some r
  | .Content _ => none
  | .Engine => none

/-- The key of the content a claim has, if any: the hash the bytes must have. -/
def contentKey : Claim → Option Dig
  | .Content k => some k
  | .Replayed k _ => some k
  | .Verity _ => none
  | .Verified _ => none
  | .Engine => none

/-- The claim names, as its fs-verity digest, a digest that is not one (a content hash): it can
never be met. -/
def Malformed (claim : Claim) : Prop :=
  ∃ e, claimedVerity claim = some e ∧ e.verity = false

/-- A digest `d` that was reported (the kernel's measure, or one computed from the bytes) is not
the fs-verity digest the claim expects. -/
def Differs (claim : Claim) (d : Option Dig) : Prop :=
  ∃ e d', claimedVerity claim = some e ∧ d = some d' ∧ ¬ Same e d'

/-- The hash of the content that was reported is not the key of the claim. -/
def KeyDiffers (claim : Claim) (content : Option Dig) : Prop :=
  ∃ k c, contentKey claim = some k ∧ content = some c ∧ ¬ Same k c

/-- The kernel's measure of the file and the fs-verity digest computed from its bytes are both
reported, and are not the same: the kernel measured a file nothing can change, so the bytes the
shell read are not the ones it measured. -/
def KernelDisagrees (seen : Seen) : Prop :=
  ∃ k m, seen.kernel = some k ∧ seen.merkle = some m ∧ ¬ Same k m

/-- The kernel's measure of the copy and the fs-verity digest computed from the bytes written into
it are both reported, and are not the same: the kernel measured a copy only the engine wrote, so a
measure that is not the digest of the bytes written means the copy is wrong. -/
def CopyDisagrees (seen : Seen) : Prop :=
  ∃ c m, seen.copy_kernel = some c ∧ seen.merkle = some m ∧ ¬ Same c m

/-- Something the shell reported disagrees with the claim or with itself: the claim cannot be
met, or the kernel's measure or the computed fs-verity digest is not the one it expects, or the
content hash is not its key, or the kernel's measure of the file is not the digest of the bytes
read, or the kernel's measure of the copy is not the digest of the bytes written.  Such a file is
refused. -/
def Mismatch (f : Facts) (seen : Seen) : Prop :=
  Malformed f.claim ∨ Differs f.claim seen.kernel ∨ Differs f.claim seen.merkle ∨
    KeyDiffers f.claim seen.content ∨ KernelDisagrees seen ∨ CopyDisagrees seen

/-- The digest the store is asked about, if it is asked: the kernel's measure, else the digest
a `Verity` claim names (before the file is opened). -/
def askedDig (claim : Claim) (kernel : Option Dig) : Option Dig :=
  match kernel, claim with
  | some m, _ => some m
  | none, .Verity v => some v
  | none, _ => none

/-- The plan asks to read the content to compare it with the key: a `Content` claim, and a
`Replayed` one that the kernel's measure does not prove (the kernel did not measure it as the
replay's digest). -/
def ReadsContent (claim : Claim) (kernel : Option Dig) : Prop :=
  match claim with
  | .Content _ => True
  | .Replayed _ r => ¬ ∃ m, kernel = some m ∧ Same m r
  | _ => False

/-- The engine itself vouches for the file: it `Verified` it, or it is an own `Replayed` file.
These are the TRUSTED cases: their digest is the engine's word. -/
def TheEngineVouches (f : Facts) : Prop :=
  (∃ v, f.claim = .Verified v) ∨ (f.own = true ∧ ∃ k r, f.claim = .Replayed k r)

/-- The shell reported only fs-verity digests as the kernel's measure, the computed digest and
the measure of the copy.  The types do not say it, so `verdict` checks it: when it is not so,
the answer is `Fail NotFsVerity`.  The claims that a file is named when the honest evidence is
seen assume it (an honest shell reports fs-verity digests there). -/
def ReportsAreFsVerity (seen : Seen) : Prop :=
  (∀ d, seen.kernel = some d → d.verity = true) ∧
  (∀ d, seen.merkle = some d → d.verity = true) ∧
  (∀ d, seen.copy_kernel = some d → d.verity = true)

/-! ### Evidence -/

/-- The claim allows `d` as the file's fs-verity digest: it expects none, or `d` is the one
it expects. -/
def Allows (claim : Claim) (d : Dig) : Prop :=
  ∀ e, claimedVerity claim = some e → Same e d

/-- The content hash the shell read is the key `k`. -/
def KeyIsRead (seen : Seen) (k : Dig) : Prop :=
  ∃ c, seen.content = some c ∧ Same k c

/-- The kernel measured the staged file as `d`. -/
def MeasuredAs (seen : Seen) (d : Dig) : Prop :=
  ∃ m, seen.kernel = some m ∧ Same m d

/-- The fs-verity digest computed from the bytes the shell read or copied is `d`. -/
def HashedAs (seen : Seen) (d : Dig) : Prop :=
  ∃ m, seen.merkle = some m ∧ Same m d

/-- The kernel measured the copy of the file as `d`. -/
def CopyMeasuredAs (seen : Seen) (d : Dig) : Prop :=
  ∃ m, seen.copy_kernel = some m ∧ Same m d

/-- The kernel measured the copy as what was computed from the bytes copied. -/
def CopyMeasured (seen : Seen) : Prop :=
  ∃ c m, seen.copy_kernel = some c ∧ seen.merkle = some m ∧ Same c m

/-- EVIDENCE (a): the kernel's measure of the file is `d`, `d` is what the claim expects (a claim
that expects no digest leaves the name to the measure: `Content` and `Engine`), and a `Content`
claim's key was read and is the content hash. -/
def KernelEvidence (f : Facts) (seen : Seen) (d : Dig) : Prop :=
  MeasuredAs seen d ∧ Allows f.claim d ∧ ∀ k, f.claim = .Content k → KeyIsRead seen k

/-- EVIDENCE (b): the bytes were read (or copied) and their computed fs-verity digest is `d`,
`d` is what the claim expects, and where the claim has a key the content hash read is the key. -/
def ReadEvidence (f : Facts) (seen : Seen) (d : Dig) : Prop :=
  HashedAs seen d ∧ Allows f.claim d ∧ ∀ k, contentKey f.claim = some k → KeyIsRead seen k

/-- EVIDENCE (c), the TRUSTED cases: the engine vouches for the file (it `Verified` it, or it is
an own replayed file) and `d` is the digest the claim says.  Nothing of the file was read or
measured: this rests on the engine's own word (THREAT-MODEL, "A store without fs-verity"). -/
def TrustedEvidence (f : Facts) (d : Dig) : Prop :=
  TheEngineVouches f ∧ ∃ e, claimedVerity f.claim = some e ∧ Same e d

/-- What it takes to name a file by `d`: one of the three evidences above. -/
def Evidence (f : Facts) (seen : Seen) (d : Dig) : Prop :=
  KernelEvidence f seen d ∨ ReadEvidence f seen d ∨ TrustedEvidence f d

/-- EVIDENCE (d), for a file that is KEPT, not named: the store already holds an object under
this name `d`; it was named by an earlier commit under these same rules; this claim (`Verity d`)
adds nothing, and the staged file is dropped unread, since it is asked of the store before the
file is opened.  With fs-verity required this holds only when the kernel measures the store's
object (`RequiredMeansMeasured`); otherwise it is an error (`AnUnmeasuredObject...`).
Nothing of the staged bytes is seen: the store's existing contents are not examined here. -/
def TheStoreHoldsIt (f : Facts) (seen : Seen) (d : Dig) : Prop :=
  seen.kernel = none ∧ f.claim = .Verity d ∧ seen.held ≠ .Lacks ∧
    (f.required = true → seen.held = .Measures)

/-! ### What the plan asked -/

/-- The shell did what the plan asked, as far as the verdict needs it: the content hash if the
plan asked for it, the computed fs-verity digest if it asked for it.  A plan that is a refusal or a
failure asks for nothing to be named (so nothing is seen that could be named). -/
def SeenWhatWasPlanned (p : Plan) (seen : Seen) : Prop :=
  match p with
  | .Keep content => content = true → seen.content ≠ none
  | .Link => True
  | .Read content merkle =>
      (content = true → seen.content ≠ none) ∧ (merkle = true → seen.merkle ≠ none)
  | .Copy content => (content = true → seen.content ≠ none) ∧ seen.merkle ≠ none
  | .Wrong _ => False
  | .Fail _ => False

/-- If the plan asks for the content hash, it was read and it is the key. -/
def TheKeyIsMet (f : Facts) (seen : Seen) : Prop :=
  ReadsContent f.claim seen.kernel → ∀ k, contentKey f.claim = some k → KeyIsRead seen k

/-! ### The claims -/

/-- **Nothing ever panics.**  `Dig::eq`, `plan`, `verdict` and `keep` return, whatever their
arguments: no digest, no claim, no facts, no report of the shell makes one of them stop.

Not said: what they return (the claims below). -/
def NothingEverPanics : Prop :=
  (∀ a b : Dig, Dig.Insts.CoreCmpPartialEqDig.eq a b ⦃ _ => True ⦄) ∧
  (∀ (f : Facts) (kernel : Option Dig) (held : Held), plan f kernel held ⦃ _ => True ⦄) ∧
  (∀ (f : Facts) (seen : Seen), verdict f seen ⦃ _ => True ⦄) ∧
  (∀ (f : Facts) (named : Named) (held : Held), keep f named held ⦃ _ => True ⦄)

/-- **`Dig::eq` is `Same`.**  It returns, and its answer is true exactly when the two digests
have the same kind, the same algorithm, the same length, and the same bytes among the first `len`
(of the 64 there are: a length above 64 is compared as far as the bytes go).

Not said: that the digests are well formed (a length above 64 is not a digest; the shell makes
only digests of 32 or 64 bytes). -/
def DigestEqualityIsSameDigest : Prop :=
  ∀ a b : Dig, Dig.Insts.CoreCmpPartialEqDig.eq a b ⦃ r => (r = true ↔ Same a b) ⦄

/-- **`Same` is an equality.**  It is reflexive, symmetric and transitive, for every digest, well
formed or not: so `Dig::eq` is an equivalence, and the digests it compares are equal in the
usual sense.

Not said: that equal digests are equal values (the bytes after `len` may differ). -/
def SameDigestIsAnEquality : Prop :=
  (∀ a : Dig, Same a a) ∧ (∀ a b : Dig, Same a b → Same b a) ∧
  (∀ a b c : Dig, Same a b → Same b c → Same a c)

/-- **A name has evidence.**  `verdict` returns, and when its answer names the file (`Name n`)
under the digest `n.verity`, there is `Evidence` (the three cases above: the kernel's measure, the
bytes read, or the engine's word); when it keeps the store's object (`Keep n`), there is
`Evidence` too, or the store already holds it (`TheStoreHoldsIt`: a `Verity` claim whose object
the store has).

Not said: that the evidence is true (the measure is of the inode that is linked, the hash is of
the bytes read: the shell's); that the trusted case is safe (it is the engine's word). -/
def NamedImpliesEvidence : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    (∀ n, v = .Name n → Evidence f seen n.verity) ∧
    (∀ n, v = .Keep n → Evidence f seen n.verity ∨ TheStoreHoldsIt f seen n.verity) ⦄

/-- **A replay of another producer is never trusted unread.**  `verdict` returns, and when the
claim is a replay (`Replayed k r`) and the file is not the engine's own, a name or a kept object
has the evidence of the kernel's measure or of the bytes read: never the engine's word.

Not said: anything of an own replayed file (it is trusted: `TrustedEvidence`). -/
def ReplayedByAnotherProducerIsNeverTrusted : Prop :=
  ∀ (f : Facts) (seen : Seen) (k r : Dig), f.claim = .Replayed k r → f.own = false →
    verdict f seen ⦃ v => ∀ n, (v = .Name n ∨ v = .Keep n) →
      KernelEvidence f seen n.verity ∨ ReadEvidence f seen n.verity ⦄

/-- **fs-verity required means measured.**  `verdict` returns, and when fs-verity is required, a
file named has `checked` and a kernel measure equal to its name: of the file when it is on the
store's file system, of its copy when it was copied; a file kept has `checked`, and the kernel
measures the store's object.

Not said: that the kernel's fs-verity is right, or what the shell does with the answer. -/
def RequiredMeansMeasured : Prop :=
  ∀ (f : Facts) (seen : Seen), f.required = true → verdict f seen ⦃ v =>
    (∀ n, v = .Name n → n.checked = true ∧
      ((f.same_fs = true ∧ MeasuredAs seen n.verity) ∨
        (f.same_fs = false ∧ CopyMeasuredAs seen n.verity))) ∧
    (∀ n, v = .Keep n → n.checked = true ∧ seen.held = .Measures) ⦄

/-- **`checked` says the kernel measured.**  `verdict` returns, and a name has `checked` exactly
when the file is on the store's file system and the kernel measured it as the name, or it was
copied and the kernel measured the copy as the name (which is what was computed from the bytes);
a kept object has it exactly when the kernel measures the store's object.

Not said: why a file is not checked (no fs-verity on its file system, or none enabled). -/
def CheckedMeansTheKernelMeasured : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    (∀ n, v = .Name n → (n.checked = true ↔
      (f.same_fs = true ∧ MeasuredAs seen n.verity) ∨
      (f.same_fs = false ∧ CopyMeasuredAs seen n.verity ∧ HashedAs seen n.verity))) ∧
    (∀ n, v = .Keep n → (n.checked = true ↔ seen.held = .Measures)) ⦄

/-- **An unmeasured store object is never kept when fs-verity is required.**  `verdict` returns,
and when fs-verity is required, the store has the object the file is asked about, and the kernel
does not measure it, the answer is a failure (`StoreUnmeasured`), or a refusal if the file
disagrees with its claim, or a failure for a report that is not an fs-verity digest
(`NotFsVerity`): never a name, never a kept object.

Not said: what happens without the requirement (the object is kept, unchecked). -/
def AnUnmeasuredObjectIsNeverKeptWhenRequired : Prop :=
  ∀ (f : Facts) (seen : Seen), f.required = true → seen.held = .Unmeasured →
    askedDig f.claim seen.kernel ≠ none →
    verdict f seen ⦃ v => (∃ why, v = .Wrong why) ∨ v = .Fail .StoreUnmeasured ∨
      v = .Fail .NotFsVerity ⦄

/-- **The store's object is never linked over.**  `verdict` returns, and when the store is asked
about an object (the kernel measured the file, or the claim names its digest) and has it, the
answer is never a name: it is a kept object, a refusal or a failure.

Not said: the case of a digest that comes from a read or a copy, which the store is asked again
(`keep`, `KeepNeverNamesWhatItWasNotGiven`). -/
def AStoreObjectIsNeverLinkedOver : Prop :=
  ∀ (f : Facts) (seen : Seen), askedDig f.claim seen.kernel ≠ none → seen.held ≠ .Lacks →
    verdict f seen ⦃ v => ∀ n, v ≠ .Name n ⦄

/-- **`keep` keeps the name it was given.**  `keep` returns, and: a name is the one it was given,
and only when the store lacks the object (so a store that has it is never linked over); a kept
object has the digest it was given, `checked` exactly when the kernel measures the store's
object, and proof `Store`; and a store that lacks the object gives the name, a store that has it
(measured, or unmeasured without the requirement) a kept object.

Not said: that the name it was given had evidence (`NamedImpliesEvidence` says it of
`verdict`, whose answer is what is given). -/
def KeepNeverNamesWhatItWasNotGiven : Prop :=
  ∀ (f : Facts) (named : Named) (held : Held), keep f named held ⦃ v =>
    (∀ m, v = .Name m → m = named ∧ held = .Lacks) ∧
    (∀ m, v = .Keep m → m.verity = named.verity ∧ held ≠ .Lacks ∧ m.proof = .Store ∧
      (m.checked = true ↔ held = .Measures)) ∧
    (held = .Lacks → v = .Name named) ∧
    (held ≠ .Lacks → (f.required = false ∨ held = .Measures) → ∃ m, v = .Keep m) ⦄

/-- **`keep` needs a measure when fs-verity is required.**  `keep` returns, and when fs-verity
is required: a store object the kernel does not measure is a failure (`StoreUnmeasured`), a
kept object is measured and `checked`, and a failure is given for nothing else.

Not said: what the shell does with the failure (it keeps the staged name). -/
def KeepNeedsAMeasureWhenRequired : Prop :=
  ∀ (f : Facts) (named : Named) (held : Held), f.required = true → keep f named held ⦃ v =>
    (held = .Unmeasured → v = .Fail .StoreUnmeasured) ∧
    (∀ m, v = .Keep m → held = .Measures ∧ m.checked = true) ∧
    (∀ why, v = .Fail why → held = .Unmeasured ∧ why = .StoreUnmeasured) ⦄

/-- **A name is an fs-verity digest.**  `verdict` returns, and the digest of a name or of a kept
object is an fs-verity digest (`verity` is true: never a content hash), and when the claim
names an fs-verity digest the name is that digest (`Allows`: the same kind, algorithm, length and
bytes).  If the claim names none, the name is the kernel's measure or the computed digest (by
`NamedImpliesEvidence`), so it has their algorithm and length.  No assumption on the shell: a
kernel measure or a computed digest that is not an fs-verity digest is a failure
(`NotFsVerity`), never a name.

Not said: that the shell reports the digests it has (the claims about `seen` are about what it
reports). -/
def ANameIsAnFsVerityDigest : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    ∀ n, (v = .Name n ∨ v = .Keep n) → n.verity.verity = true ∧ Allows f.claim n.verity ⦄

/-- **The verdict is for the plan.**  `verdict` returns, and when it names a file or keeps the
store's object, the plan `plan` makes for these facts and this kernel measure and store (the
verdict makes it again: the shell cannot pass another) was to keep the object (for a kept one)
or to link, read or copy the file (for a name), and the shell did everything that plan asked
(`SeenWhatWasPlanned`).  So with less seen than the plan asked, the verdict never names: it
fails.

Not said: that the shell did what the plan said (it reports what it did). -/
def TheVerdictIsForThePlan : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    ∃ p, plan f seen.kernel seen.held = ok p ∧
      ((∃ n, v = .Keep n) → (∃ c, p = .Keep c) ∧ SeenWhatWasPlanned p seen) ∧
      ((∃ n, v = .Name n) →
        (p = .Link ∨ (∃ c m, p = .Read c m) ∨ ∃ c, p = .Copy c) ∧ SeenWhatWasPlanned p seen) ⦄

/-- **The plan fits the file system.**  `plan` returns, and it copies a file only when its staging
is not on the store's file system, and links or reads it only when it is.

Not said: that the shell can link a file of the same file system (the inode check of the link). -/
def ThePlanFitsTheFileSystem : Prop :=
  ∀ (f : Facts) (kernel : Option Dig) (held : Held), plan f kernel held ⦃ p =>
    (∀ c, p = .Copy c → f.same_fs = false) ∧
    ((p = .Link ∨ ∃ c m, p = .Read c m) → f.same_fs = true) ⦄

/-- **Only the trusted are linked unread.**  `plan` returns, and when it says to link a file, with
no read of its bytes: the kernel measured it and the plan asks for no content hash (the kernel's
measure is the evidence), or the kernel measured nothing, fs-verity is not required, and the
engine vouches for it (`TheEngineVouches`).  Every other file is measured, read or copied.

Not said: that the vouching is true. -/
def OnlyTrustedFilesAreLinkedUnread : Prop :=
  ∀ (f : Facts) (kernel : Option Dig) (held : Held), plan f kernel held ⦃ p =>
    p = .Link → (kernel ≠ none ∧ ¬ ReadsContent f.claim kernel) ∨
      (kernel = none ∧ f.required = false ∧ TheEngineVouches f) ⦄

/-- **A refusal exactly when a digest disagrees.**  `verdict` returns, and the answer is a
refusal (`Wrong`) exactly when the claim cannot be met, or the kernel's measure, or the computed
fs-verity digest, is not the fs-verity digest the claim expects, or the content hash is not the
key, or the kernel's measure of the file or of the copy is not the digest of the bytes
(`Mismatch`): so a file that agrees with its claim is never refused, and one that does not
is always.

Not said: which `Why` it gives when several disagree. -/
def WrongExactlyWhenADigestDisagrees : Prop :=
  ∀ (f : Facts) (seen : Seen),
    verdict f seen ⦃ v => ((∃ why, v = .Wrong why) ↔ Mismatch f seen) ⦄

/-- **A failure has its reason.**  `verdict` returns, and a failure is never `NotPlanned` (the
plan and the verdict disagree, an internal bug: it is never returned), and `NoMeasure` and
`StoreUnmeasured` are given only when fs-verity is required.

Not said: when `Unread` is given (see `TheVerdictIsForThePlan`: a step the plan asked for was not
seen). -/
def AFailureHasItsReason : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    ∀ why, v = .Fail why → why ≠ .NotPlanned ∧
      ((why = .NoMeasure ∨ why = .StoreUnmeasured) → f.required = true) ⦄

/-- **The proof `Kernel` is exactly the kernel's evidence, asked of the store.**  `verdict`
returns, and: a name has the proof `Kernel` exactly when the file is on the store's file system
and the kernel measured it as the name; then the store was asked about this very name and
lacks the object (so linking is safe).  A kept object has the proof `Kernel` exactly when the kernel
measured the file (else `Store`: the claim's word).  This is what lets the shell skip the second
question (`keep`) for the names with the proof `Kernel`, and only for them.

Not said: that the shell asks `keep` for the others. -/
def AKernelProofMeansTheStoreWasAsked : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    (∀ n, v = .Name n → (n.proof = .Kernel ↔ f.same_fs = true ∧ seen.kernel = some n.verity) ∧
      (n.proof = .Kernel →
        askedDig f.claim seen.kernel = some n.verity ∧ seen.held = .Lacks)) ∧
    (∀ n, v = .Keep n → (n.proof = .Kernel ↔ seen.kernel ≠ none)) ⦄

/-- **No name against the measure.**  `verdict` returns, and when it names a file or keeps the
store's object, a kernel measure and a digest computed from the bytes that were both reported are
the same, and so are the kernel's measure of the copy and the digest computed from the bytes
written into it, when both were reported: a file is never named against a kernel measure that
disagrees with the bytes read or written.

Not said: that the kernel's measure is of the bytes the shell read (the shell's). -/
def NoNameAgainstTheMeasure : Prop :=
  ∀ (f : Facts) (seen : Seen), verdict f seen ⦃ v =>
    ∀ n, (v = .Name n ∨ v = .Keep n) →
      (∀ k m, seen.kernel = some k → seen.merkle = some m → Same k m) ∧
      (∀ c m, seen.copy_kernel = some c → seen.merkle = some m → Same c m) ⦄

/-- **A measured file is named (liveness).**  The kernel measured the staged file as `m`, nothing
the shell reported disagrees with the claim, a `Content` or `Replayed` claim's key was read when
the plan asked, the store lacks the object, and the file is on the store's file system: then
the answer is the name `m`, `checked`, with proof `Kernel`.  (A core that refuses everything does
not satisfy this.)

Not said: the other cases (`AReadFileIsNamed`, ...). -/
def AMeasuredFileIsNamed : Prop :=
  ∀ (f : Facts) (seen : Seen) (m : Dig), ¬ Mismatch f seen → ReportsAreFsVerity seen →
    seen.held = .Lacks →
    f.same_fs = true → seen.kernel = some m → TheKeyIsMet f seen →
    verdict f seen ⦃ v => v = .Name ⟨m, true, .Kernel⟩ ⦄

/-- **A file whose bytes were read is named (liveness).**  The kernel measured nothing, fs-verity
is not required, the file is on the store's file system, nothing reported disagrees with the claim,
the engine does not vouch for it (that case is the next claim), the store lacks the object, the
shell read the bytes and computed the fs-verity digest `d`, and where the claim has a key the
content hash read is the key: then the answer is the name `d`, not `checked`.

Not said: the same file when the kernel measures it (`AMeasuredFileIsNamed`). -/
def AReadFileIsNamed : Prop :=
  ∀ (f : Facts) (seen : Seen) (d : Dig), ¬ Mismatch f seen → ReportsAreFsVerity seen →
    seen.held = .Lacks →
    f.same_fs = true → seen.kernel = none → f.required = false → ¬ TheEngineVouches f →
    seen.merkle = some d → TheKeyIsMet f seen →
    verdict f seen ⦃ v => ∃ n, v = .Name n ∧ n.verity = d ∧ n.checked = false ⦄

/-- **A copied file is named (liveness).**  The file is not on the store's file system, nothing
reported disagrees with the claim, the store lacks the object, the shell copied it and computed
the fs-verity digest `d`, the key was read when the plan asked, and, when fs-verity is required,
the kernel measured the copy as `d`: then the answer is the name `d`, `checked` exactly when the
kernel measured the copy.

Not said: that the copy is of the bytes that were hashed (the shell's). -/
def ACopiedFileIsNamed : Prop :=
  ∀ (f : Facts) (seen : Seen) (d : Dig), ¬ Mismatch f seen → ReportsAreFsVerity seen →
    seen.held = .Lacks →
    f.same_fs = false → seen.merkle = some d → TheKeyIsMet f seen →
    (f.required = true → CopyMeasured seen) →
    verdict f seen ⦃ v => ∃ n, v = .Name n ∧ n.verity = d ∧ (n.checked = true ↔ CopyMeasured seen) ⦄

/-- **A file the engine vouches for is named (liveness).**  The kernel measured nothing,
fs-verity is not required, the file is on the store's file system, the engine vouches for it
(`TheEngineVouches`: it `Verified` it, or it is an own replayed file), and nothing reported
disagrees with the claim: then the answer is the name the claim says, not `checked`, with proof
`Trusted`: unread, on the engine's word.

Not said: that the word is true. -/
def AFileTheEngineVouchesForIsNamed : Prop :=
  ∀ (f : Facts) (seen : Seen) (d : Dig), ¬ Mismatch f seen → ReportsAreFsVerity seen →
    seen.held = .Lacks →
    f.same_fs = true → seen.kernel = none → f.required = false → TheEngineVouches f →
    claimedVerity f.claim = some d →
    verdict f seen ⦃ v => v = .Name ⟨d, false, .Trusted⟩ ⦄

/-- **An object the store has is kept (liveness).**  The store has the object the file is asked
about (`askedDig`: the kernel's measure, else the digest of a `Verity` claim), it is measured, or
fs-verity is not required, nothing reported disagrees with the claim, and the key was read
when the plan asked: then the answer is to keep it, under that digest, `checked` exactly
when the kernel measures the store's object.

Not said: the file is not linked (it is dropped, the staged name). -/
def AKnownObjectIsKept : Prop :=
  ∀ (f : Facts) (seen : Seen) (d : Dig), ¬ Mismatch f seen → ReportsAreFsVerity seen →
    seen.held ≠ .Lacks →
    askedDig f.claim seen.kernel = some d → (f.required = false ∨ seen.held = .Measures) →
    TheKeyIsMet f seen →
    verdict f seen ⦃ v => ∃ n, v = .Keep n ∧ n.verity = d ∧
      (n.checked = true ↔ seen.held = .Measures) ⦄

end CommitCore
