-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `Dig::eq` (crates/commit-core, src/lib.rs) returns:
-- `eq_loop_spec` says that it returns, and that it answers "true" exactly when the answer it
-- was given before it started was "true" and the bytes from the place it starts at, as far as
-- the length of the digest goes, are the same in the two digests.
--
-- Why it is needed: `Dig::eq` is the only loop of the crate.  It compares the digests byte by
-- byte, and stops at the first byte that differs or at the length.  Every other claim
-- is about digests being the same (`Same` in Spec.lean), so this is where the loop is turned into
-- that sentence, once.  DigestEquality of the next files uses it.
--
-- Read before this file: Spec.lean (`Same`), and `Dig::eq` in src/lib.rs.
--
-- Notation: `x ⦃ r => P r ⦄` is "the function returns, and its result `r` satisfies `P r`";
-- `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn (here
-- the bytes not yet compared) and a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩`
-- runs one Rust line and names its result `x` and what is known of it `hx`; `l[j]?` is the
-- element `j` of the list `l` if there is one.
import CommitCore.Spec
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- The two lists have the same elements from the place `k` on, as far as `len`. -/
def AgreeFrom (len : Nat) (a b : List Std.U8) (k : Nat) : Prop :=
  ∀ j : Nat, k ≤ j → j < len → a[j]? = b[j]?

/-- To agree from `k` is to agree at `k` and from the next place on, when `k` is below `len`. -/
theorem agree_from_one_more {len : Nat} {a b : List Std.U8} {k : Nat} (inside : k < len) :
    AgreeFrom len a b k ↔ a[k]? = b[k]? ∧ AgreeFrom len a b (k + 1) := by
  constructor
  · intro all
    exact ⟨all k (Nat.le_refl k) inside, fun j later below => all j (by omega) below⟩
  · rintro ⟨here, rest⟩ j from_k below
    rcases Nat.eq_or_lt_of_le from_k with rfl | later
    · exact here
    · exact rest j later below

/-- From `len` on there is nothing left to compare: any two lists agree. -/
theorem agree_from_past_the_end {len : Nat} {a b : List Std.U8} {k : Nat} (past : len ≤ k) :
    AgreeFrom len a b k := fun j from_k below => by omega

/-- The loop of `Dig::eq`, started at the place `k` with the answer `same` of what was compared
before, returns `true` exactly when `same` is true and the bytes agree from `k` to the length. -/
theorem eq_loop_spec (len : Std.U8) (a b : Array Std.U8 64#usize) (same : Bool)
    (k : Std.Usize) :
    Dig.Insts.CoreCmpPartialEqDig.eq_loop len a b same k ⦃ r =>
      (r = true ↔ same = true ∧ AgreeFrom len.val a.val b.val k.val) ⦄ := by
  unfold Dig.Insts.CoreCmpPartialEqDig.eq_loop
  -- the invariant: what the loop would answer from where it is, is what it would answer from
  -- the start; the number that goes down is the bytes there are left of the 64
  apply loop.spec_decr_nat (fun q => 64 - q.2.val)
    (fun q => (q.1 = true ∧ AgreeFrom len.val a.val b.val q.2.val) ↔
      (same = true ∧ AgreeFrom len.val a.val b.val k.val))
    (fun r => (r = true ↔ same = true ∧ AgreeFrom len.val a.val b.val k.val))
  · rintro ⟨s, i⟩ inv
    simp only at inv ⊢
    unfold Dig.Insts.CoreCmpPartialEqDig.eq_loop.body
    split
    · rename_i still_same
      simp only [lift, Std.bind_ok]
      split
      · rename_i inside
        split
        · rename_i below
          have inside : i.val < len.val := by scalar_tac
          have below : i.val < 64 := by scalar_tac
          step as ⟨ x, hx ⟩
          step as ⟨ y, hy ⟩
          step as ⟨ next, hnext ⟩
          -- the byte `i` is compared, and the loop goes on at `i + 1`
          refine ⟨?_, by scalar_tac⟩
          have bytes_here : (↑a : List Std.U8)[i.val]? = (↑b : List Std.U8)[i.val]? ↔ x = y := by
            have x_is : (↑a : List Std.U8)[i.val]? = some x := by
              rw [hx]; exact List.getElem?_eq_getElem (by scalar_tac)
            have y_is : (↑b : List Std.U8)[i.val]? = some y := by
              rw [hy]; exact List.getElem?_eq_getElem (by scalar_tac)
            rw [x_is, y_is]
            simp
          rw [← inv, agree_from_one_more inside, bytes_here, hnext, still_same]
          simp
        · -- the byte is beyond the 64 there are: nothing is left to compare
          have past : 64 ≤ i.val := by scalar_tac
          simp only [WP.spec_ok]
          rw [← inv, still_same]
          have rest : AgreeFrom len.val a.val b.val i.val := by
            intro j from_i below
            have a_past : a.val[j]? = none :=
              List.getElem?_eq_none (by have := a.property; scalar_tac)
            have b_past : b.val[j]? = none :=
              List.getElem?_eq_none (by have := b.property; scalar_tac)
            rw [a_past, b_past]
          simp [rest]
      · -- all `len` bytes have been compared
        have past : len.val ≤ i.val := by scalar_tac
        simp only [WP.spec_ok]
        rw [← inv, still_same]
        simp [agree_from_past_the_end past]
    · -- an earlier byte differed
      rename_i different
      simp only [WP.spec_ok]
      have not_same : s = false := by simpa using different
      rw [← inv, not_same]
      simp
  · exact Iff.rfl

end CommitCore
