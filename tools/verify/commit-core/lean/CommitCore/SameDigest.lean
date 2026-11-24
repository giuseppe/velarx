-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `Same` (Spec.lean), the sentence "these two digests are the same",
-- is an equality: it is reflexive, symmetric and transitive.
--
-- Why it is needed: the claims chain digests (the claim's digest is the same as the one the
-- kernel measured, which is the same as the name), so they use transitivity; the claim
-- `SameDigestIsAnEquality` of Spec.lean is these three theorems.
--
-- Read before this file: Spec.lean (`Same`).
--
-- Notation: `Same a b` is "the digests `a` and `b` have the same kind, algorithm, length and bytes
-- as far as the length goes"; `obtain ⟨x, y⟩ := h` takes a statement `h` of the form "x and y"
-- apart.
import CommitCore.Spec
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- A digest is the same as itself. -/
theorem same_refl (a : Dig) : Same a a :=
  ⟨rfl, rfl, rfl, fun _ _ => rfl⟩

/-- If `a` is the same as `b`, `b` is the same as `a`. -/
theorem same_symm {a b : Dig} (same : Same a b) : Same b a := by
  obtain ⟨verity, alg, len, bytes⟩ := same
  refine ⟨verity.symm, alg.symm, len.symm, fun i below => ?_⟩
  exact (bytes i (len ▸ below)).symm

/-- If `a` is the same as `b` and `b` as `c`, `a` is the same as `c`. -/
theorem same_trans {a b c : Dig} (ab : Same a b) (bc : Same b c) : Same a c := by
  obtain ⟨verity, alg, len, bytes⟩ := ab
  obtain ⟨verity', alg', len', bytes'⟩ := bc
  exact ⟨verity.trans verity', alg.trans alg', len.trans len', fun i below =>
    (bytes i below).trans (bytes' i (len ▸ below))⟩

end CommitCore
