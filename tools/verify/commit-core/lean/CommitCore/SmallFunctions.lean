-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what each small function of crates/commit-core (src/lib.rs) returns,
-- in the words of Spec.lean: `Dig::eq` (true when the digests are `Same`), `malformed`,
-- `differs`, `reads_content`, `reported`, `reports_fs_verity`, the comparison of two optional
-- digests (`measured_as`) and of two states of the store, and `asked`, `key_of`.
-- Each is a statement "the function returns, and its answer
-- is such and such".
--
-- Why it is needed: `plan` and `verdict` are built of these functions.  The proofs of the
-- next files (ThePlan.lean, TheVerdict.lean) use them instead of unfolding the code each
-- time, so a reader of those files sees "the claim has a digest that is not the one expected"
-- where Aeneas wrote a call and a match.
--
-- Read before this file: Spec.lean, DigestCompare.lean, and the small functions of src/lib.rs.
--
-- Notation: `x ⦃ r => P r ⦄` is "the function returns, and its result `r` satisfies `P r`";
-- `refine WP.spec_bind h ?_` is "first run the function `h` is about, then go on with what is
-- known of its result"; `WP.spec_mono h ?_` is "the result satisfies something that implies
-- what was asked"; `o = none` is "the answer is `None`"; `cases x` makes one case of each way
-- `x` can be; `simp` rewrites with what it knows.
import CommitCore.DigestCompare
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- `Dig::eq` returns, and says "true" exactly when the digests are the same (`Same`): the loop of
the previous file is started at the first byte, with the kind, algorithm and length compared. -/
theorem dig_eq_spec (a b : Dig) :
    Dig.Insts.CoreCmpPartialEqDig.eq a b ⦃ r => (r = true ↔ Same a b) ⦄ := by
  unfold Dig.Insts.CoreCmpPartialEqDig.eq
  by_cases verity : a.verity = b.verity <;> by_cases alg : a.alg = b.alg <;>
    by_cases len : a.len = b.len <;> simp only [verity, alg, len, ↓reduceIte, Std.bind_ok] <;>
    refine WP.spec_mono (eq_loop_spec _ _ _ _ _) ?_ <;> intro r loop <;> rw [loop] <;>
    simp [Same, AgreeFrom, verity, alg, len]

/-- `!=` of two digests (the default `ne` of the trait, which calls `eq`) says "true" exactly when
the digests are not the same. -/
theorem dig_ne_spec (a b : Dig) :
    core.cmp.PartialEq.ne.trait_default Dig.Insts.CoreCmpPartialEqDig a b ⦃ r =>
      (r = true ↔ ¬ Same a b) ⦄ := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  refine WP.spec_bind (dig_eq_spec a b) ?_
  intro r same
  simp only [WP.spec_ok]
  cases r <;> simp_all

/-- `malformed` gives no refusal exactly when the claim is not `Malformed` (it expects, as its
fs-verity digest, a digest that is one). -/
theorem malformed_spec (claim : Claim) :
    malformed claim ⦃ o => (o = none ↔ ¬ Malformed claim) ⦄ := by
  cases claim <;> simp [malformed, expected, Malformed, claimedVerity] <;> split <;> simp_all

/-- `differs` gives no refusal exactly when the digest reported does not `Differ` from what the
claim expects (`computed1` only says which reason the refusal carries). -/
theorem differs_spec (claim : Claim) (d : Option Dig) (computed1 : Bool) :
    differs claim d computed1 ⦃ o => (o = none ↔ ¬ Differs claim d) ⦄ := by
  cases claim <;> cases d <;> cases computed1 <;>
    simp [differs, expected, Differs, claimedVerity] <;>
    refine WP.spec_bind (dig_ne_spec _ _) ?_ <;> intro b hb <;> split <;> simp_all

/-- `measured_as` says "true" exactly when both digests are there and are the same. -/
theorem measured_as_spec (a b : Option Dig) :
    measured_as a b ⦃ r => (r = true ↔ ∃ x y, a = some x ∧ b = some y ∧ Same x y) ⦄ := by
  cases a <;> cases b <;> simp [measured_as]
  exact dig_eq_spec _ _

/-- `disagree` says "true" exactly when both digests are there and are not the same. -/
theorem disagree_spec (a b : Option Dig) :
    disagree a b ⦃ r => (r = true ↔ ∃ x y, a = some x ∧ b = some y ∧ ¬ Same x y) ⦄ := by
  cases a <;> cases b <;> simp [disagree]
  exact WP.spec_mono (dig_ne_spec _ _) (fun _ is_ne => is_ne)

/-- `is_fs_verity` says "true" for no digest and for an fs-verity digest. -/
theorem is_fs_verity_spec (d : Option Dig) :
    is_fs_verity d ⦃ r => (r = true ↔ ∀ x, d = some x → x.verity = true) ⦄ := by
  cases d <;> simp [is_fs_verity]

/-- `reports_fs_verity` says "true" exactly when what the shell reported as the kernel's
measure, the computed digest and the measure of the copy are fs-verity digests. -/
theorem reports_fs_verity_spec (seen : Seen) :
    reports_fs_verity seen ⦃ r => (r = true ↔ ReportsAreFsVerity seen) ⦄ := by
  unfold reports_fs_verity
  refine WP.spec_bind (is_fs_verity_spec seen.kernel) ?_
  intro kernel is_kernel
  cases kernel with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
    exact ⟨fun no => absurd no (by simp), fun reports => absurd (is_kernel.mpr reports.1) (by simp)⟩
  | true =>
    simp only [↓reduceIte]
    refine WP.spec_bind (is_fs_verity_spec seen.merkle) ?_
    intro merkle is_merkle
    cases merkle with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      exact ⟨fun no => absurd no (by simp),
        fun reports => absurd (is_merkle.mpr reports.2.1) (by simp)⟩
    | true =>
      simp only [↓reduceIte]
      refine WP.spec_mono (is_fs_verity_spec seen.copy_kernel) ?_
      intro copy is_copy
      rw [is_copy]
      simp only [ReportsAreFsVerity]
      have kernel_ok := is_kernel.mp rfl
      have merkle_ok := is_merkle.mp rfl
      exact ⟨fun h => ⟨kernel_ok, merkle_ok, h⟩, fun h => h.2.2⟩

/-- `key_of` is `contentKey` of Spec.lean. -/
theorem key_of_eq (claim : Claim) : key_of claim = ok (contentKey claim) := by
  cases claim <;> rfl

/-- `asked` is `askedDig` of Spec.lean. -/
theorem asked_eq (claim : Claim) (kernel : Option Dig) :
    asked claim kernel = ok (askedDig claim kernel) := by
  cases claim <;> cases kernel <;> rfl

/-- `reads_content` says "true" exactly when the plan reads the content (`ReadsContent`). -/
theorem reads_content_spec (claim : Claim) (kernel : Option Dig) :
    reads_content claim kernel ⦃ b => (b = true ↔ ReadsContent claim kernel) ⦄ := by
  cases claim <;> simp [reads_content, ReadsContent]
  refine WP.spec_bind (measured_as_spec _ _) ?_
  intro b is_same
  simp only [WP.spec_ok]
  cases b <;> simp_all

/-- `reported` gives no refusal exactly when nothing the shell reported disagrees with the claim
(`Mismatch`): the claim is well formed, the kernel's measure and the computed digest are the
ones it expects, the kernel's measures of the file and of the copy are the computed digest, and
the content hash is its key. -/
theorem reported_spec (f : Facts) (seen : Seen) :
    reported f seen ⦃ o => (o = none ↔ ¬ Mismatch f seen) ⦄ := by
  unfold reported
  -- first the claim, then the kernel's measure, then the computed digest, then the two
  -- measures against the digest, then the key
  refine WP.spec_bind (malformed_spec f.claim) ?_
  intro malformed_claim is_malformed
  cases malformed_claim with
  | some why =>
    simp only [WP.spec_ok]
    have : Malformed f.claim := by simpa using is_malformed
    simp [Mismatch, this]
  | none =>
    have fine : ¬ Malformed f.claim := by simpa using is_malformed
    refine WP.spec_bind (differs_spec f.claim seen.kernel false) ?_
    intro kernel_differs is_kernel
    cases kernel_differs with
    | some why =>
      simp only [WP.spec_ok]
      have : Differs f.claim seen.kernel := by simpa using is_kernel
      simp [Mismatch, this]
    | none =>
      have same_kernel : ¬ Differs f.claim seen.kernel := by simpa using is_kernel
      refine WP.spec_bind (differs_spec f.claim seen.merkle true) ?_
      intro merkle_differs is_merkle
      cases merkle_differs with
      | some why =>
        simp only [WP.spec_ok]
        have : Differs f.claim seen.merkle := by simpa using is_merkle
        simp [Mismatch, this]
      | none =>
        have same_merkle : ¬ Differs f.claim seen.merkle := by simpa using is_merkle
        refine WP.spec_bind (disagree_spec seen.kernel seen.merkle) ?_
        intro apart is_apart
        cases apart with
        | true =>
          simp only [↓reduceIte, WP.spec_ok]
          have : KernelDisagrees seen := is_apart.mp rfl
          simp [Mismatch, this]
        | false =>
          have agree : ¬ KernelDisagrees seen := fun apart => by simpa using is_apart.mpr apart
          simp only [Bool.false_eq_true, ↓reduceIte]
          -- then the kernel's measure of the copy against the computed digest
          refine WP.spec_bind (disagree_spec seen.copy_kernel seen.merkle) ?_
          intro copy_apart is_copy_apart
          cases copy_apart with
          | true =>
            simp only [↓reduceIte, WP.spec_ok]
            have : CopyDisagrees seen := is_copy_apart.mp rfl
            simp [Mismatch, this]
          | false =>
            have copy_agrees : ¬ CopyDisagrees seen := fun apart => by
              simpa using is_copy_apart.mpr apart
            simp only [Bool.false_eq_true, ↓reduceIte]
            -- last the content hash against the key
            rw [key_of_eq]
            simp only [Std.bind_ok]
            cases claim_key : contentKey f.claim with
            | none =>
              simp [Mismatch, fine, same_kernel, same_merkle, agree, copy_agrees, KeyDiffers,
                claim_key]
            | some k =>
              cases seen_content : seen.content with
              | none =>
                simp [Mismatch, fine, same_kernel, same_merkle, agree, copy_agrees, KeyDiffers,
                  seen_content]
              | some c =>
                simp only
                refine WP.spec_bind (dig_ne_spec k c) ?_
                intro b is_ne
                split
                · simp only [WP.spec_ok]
                  simp_all [Mismatch, KeyDiffers]
                · simp only [WP.spec_ok]
                  simp_all [Mismatch, KeyDiffers]

/-- `==` of two states of the store says "true" exactly when they are the same state. -/
theorem held_eq_spec (a b : Held) :
    Held.Insts.CoreCmpPartialEqHeld.eq a b ⦃ r => (r = true ↔ a = b) ⦄ := by
  cases a <;> cases b <;> simp [Held.Insts.CoreCmpPartialEqHeld.eq, Held.read_discriminant]

/-- `!=` of two states of the store says "true" exactly when they are different. -/
theorem held_ne_spec (a b : Held) :
    core.cmp.PartialEq.ne.trait_default Held.Insts.CoreCmpPartialEqHeld a b ⦃ r =>
      (r = true ↔ a ≠ b) ⦄ := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  refine WP.spec_bind (held_eq_spec a b) ?_
  intro r same
  simp only [WP.spec_ok]
  cases r <;> simp_all

/-- A function that returns what a statement says it returns: the value it returned. -/
theorem spec_gives_ok {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ P ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis i k => exact absurd h (by simp [WP.spec_vis])
  | div => exact absurd h (by simp [WP.spec_div])

end CommitCore
