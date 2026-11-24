-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the small functions on names that `select` is made of, one answer
-- each: `same`, `starts`, `covers` and `host_len`; with the facts about slices and vectors they
-- need (the length of a slice is a number, a vector seen as a slice has its bytes).
--
-- Why it is needed: `covers` is `CoversName` and `host_len` is the length of `host` of
-- Spec.lean; the later files use these answers, never the code of the loops.
--
-- Read before this file: Spec.lean, Bytes.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Bytes
import PolicyCore.Spec
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- The lengths of two slices are the same `usize` exactly when they are the same number. -/
theorem len_eq_iff {α : Type} (a b : Slice α) :
    Slice.len a = Slice.len b ↔ a.length = b.length := by
  constructor
  · intro h
    simpa [Slice.len] using congrArg UScalar.val h
  · intro h
    simp only [Slice.len]
    congr

/-- The same for "not longer". -/
theorem len_le_iff {α : Type} (a b : Slice α) :
    Slice.len a ≤ Slice.len b ↔ a.length ≤ b.length := by
  simp only [Slice.len]
  rw [UScalar.le_equiv]
  simp [Slice.length]

/-- An index is the length of a slice exactly when it is that number. -/
theorem index_eq_len_iff {α : Type} (i : Std.Usize) (a : Slice α) :
    i = Slice.len a ↔ i.val = a.length := by
  rw [UScalar.eq_equiv]
  simp [Slice.len, Slice.length]

/-- Looking at a vector as a slice keeps its bytes. -/
@[simp]
theorem deref_val {α : Type} (v : alloc.vec.Vec α) : v.deref.val = v.val := by
  simp [alloc.vec.Vec.deref, Slice.from, Slice.val, Data.ListN.ListN.from_to_inverse]

/-- `same` compares the bytes. -/
@[step]
theorem same_is_equal (a b : Slice Std.U8) : same a b ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same
  apply same_loop_is_equal
  · simp
  · rw [decide_eq_true_iff]
    rw [len_eq_iff]
    simp
/-- `starts` says whether `a` is the beginning of `b`. -/
@[step]
theorem starts_is_prefix (a b : Slice Std.U8) : starts a b ⦃ r => r = true ↔ a.val <+: b.val ⦄ := by
  unfold starts
  apply starts_loop_is_prefix
  · simp
  · rw [decide_eq_true_iff, len_le_iff]
    simp
/-- `covers` says whether `scope` is a repository, a namespace or a host of the name. -/
@[step]
theorem covers_is_covers_name (scope full : Slice Std.U8) :
    covers scope full ⦃ r => r = true ↔ CoversName scope.val full.val ⦄ := by
  unfold covers
  step as ⟨ b, hb ⟩
  split
  · rename_i begins
    obtain ⟨short, agree⟩ := (prefix_iff_agree _ _).mp (hb.mp begins)
    dsimp only [Slice.len]
    split
    · rename_i same_length
      -- the lengths are the same: the scope is the whole name
      have equal_length : scope.val.length = full.val.length :=
        (len_eq_iff scope full).mp same_length
      simp only [WP.spec_ok, true_iff]
      exact ⟨hb.mp begins, Or.inl ((hb.mp begins).eq_of_length equal_length)⟩
    · rename_i longer
      -- the name is longer: the byte after the scope must be a `/`
      have shorter : scope.length < full.length := by
        have := (len_eq_iff scope full).not.mp longer
        simp only [Slice.length] at this ⊢
        omega
      step as ⟨ x, hx ⟩
      have after_scope : full.val[scope.val.length]? = some x := by simp [hx]
      rw [decide_eq_true_iff]
      constructor
      · intro is_slash
        exact ⟨hb.mp begins, Or.inr (by rw [after_scope, is_slash]; rfl)⟩
      · rintro ⟨_, same_name | slash_after⟩
        · simp only [Slice.length] at shorter
          rw [same_name] at shorter
          omega
        · rw [after_scope] at slash_after
          exact Option.some.inj slash_after
  · rename_i not_begins
    -- the scope is not even the beginning
    simp only [WP.spec_ok, Bool.false_eq_true, false_iff]
    exact fun covered => not_begins (hb.mpr covered.1)
/-- The length of what `List.takeWhile` keeps: every element before it passes, and the next
one, if there is one, does not. -/
theorem takeWhile_length_is {α : Type} (keep : α → Bool) (l : List α) (n : Nat)
    (within : n ≤ l.length) (kept : ∀ k < n, ∃ x, l[k]? = some x ∧ keep x = true)
    (stops : n = l.length ∨ ∃ x, l[n]? = some x ∧ keep x = false) :
    (l.takeWhile keep).length = n := by
  induction l generalizing n with
  | nil => simpa using within
  | cons first rest ih =>
    cases n with
    | zero =>
      rcases stops with at_end | ⟨x, hx, dropped⟩
      · simp at at_end
      · simp only [List.getElem?_cons_zero, Option.some.injEq] at hx
        subst hx
        simp [dropped]
    | succ n =>
      obtain ⟨x, hx, passes⟩ := kept 0 (by omega)
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hx
      subst hx
      have rest_kept : ∀ k < n, ∃ x, rest[k]? = some x ∧ keep x = true :=
        fun k below => kept (k + 1) (by omega)
      have := ih n (by simpa using within) rest_kept (by simpa using stops)
      simp [passes, this]
/-- `host_len` is the length of the host. -/
@[step]
theorem host_len_is (full : Slice Std.U8) :
    host_len full ⦃ n => n.val = (host full.val).length ⦄ := by
  unfold host_len host_len_loop host
  apply loop.spec_decr_nat (fun n => full.length - n.val)
    (fun n => n.val ≤ full.length ∧ ∀ k < n.val, ∃ x, full.val[k]? = some x ∧
      (x != slash && x != colon) = true)
  · intro n ⟨within, kept⟩
    unfold host_len_loop.body
    dsimp only [Slice.len]
    split
    · rename_i below
      step as ⟨ x, hx ⟩
      have inside : n.val < full.length := by scalar_tac
      have x_is : full.val[n.val]? = some x := by simp [hx]
      -- a `/` or a `:` ends the host, at the position `n`
      have ends_here : ¬ (x != slash && x != colon) = true →
          n.val = (List.takeWhile (fun c => c != slash && c != colon) full.val).length := by
        intro stops
        exact (takeWhile_length_is _ _ n.val (by simpa [Slice.length] using within) kept
          (Or.inr ⟨x, x_is, Bool.eq_false_iff.mpr stops⟩)).symm
      have keep_is : (x != slash && x != colon) = ((x != 47#u8) && (x != 58#u8)) := rfl
      cases is_slash : (x != 47#u8)
      · simp only [Bool.false_eq_true, ↓reduceIte]
        refine (WP.spec_ok _).mpr (ends_here ?_)
        simp [keep_is, is_slash]
      · cases is_colon : (x != 58#u8)
        · simp only [Bool.false_eq_true, ↓reduceIte]
          refine (WP.spec_ok _).mpr (ends_here ?_)
          simp [keep_is, is_colon]
        · -- neither: the host goes on
          simp only [↓reduceIte]
          step as ⟨ next, hnext ⟩
          refine ⟨by omega, fun k before => ?_, by omega⟩
          rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : k < n.val + 1) with earlier | at_n
          · exact kept k earlier
          · exact ⟨x, by rw [at_n]; exact x_is, by rw [keep_is, is_slash, is_colon]; rfl⟩
    · rename_i at_end
      -- the end of the name ends the host
      simp only [WP.spec_ok]
      have : n.val = full.length := by scalar_tac
      exact (takeWhile_length_is _ _ n.val (by omega) kept
        (Or.inl (by simpa [Slice.length] using this))).symm
  · simp
end PolicyCore
