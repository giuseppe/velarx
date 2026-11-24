-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `wildcard_covers` (the scope is `*.suffix` and the host of the name ends
-- with `.suffix`): what its loop checks, byte by byte, and that this is `IsWildcardOf` of
-- Spec.lean.
--
-- Why it is needed: the code compares the scope with the end of the host by indexes counted from
-- the end of the host (`name[host - (len - i)]`); the proof shows that these indexes are always
-- inside the name, and that the comparison is "the end of the host is `.suffix`".
--
-- Read before this file: Scope.lean, Joined.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Joined
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- The host is the beginning of the name, so it reads as the name does. -/
theorem host_reads_as_name (full : List Std.U8) (k : Nat) (inside : k < (host full).length) :
    (host full)[k]? = full[k]? := by
  have begins : host full <+: full := List.takeWhile_prefix _
  obtain ⟨_, agree⟩ := (prefix_iff_agree _ _).mp begins
  exact agree k inside

/-- What `wildcard_covers` checks first, with the length of the host `h` given: the scope starts
with `*.` and what follows the `*` is not longer than the host. -/
def WildcardHead (scope : List Std.U8) (h : Nat) : Prop :=
  2 ≤ scope.length ∧ scope[0]? = some star ∧ scope[1]? = some dot ∧ scope.length - 1 ≤ h

/-- What `wildcard_covers` checks in all: the head, and each byte of the scope after the `*` is
the byte of the name that many places before the end of the host. -/
def WildcardBytes (scope full : List Std.U8) (h : Nat) : Prop :=
  WildcardHead scope h ∧
  ∀ k, 1 ≤ k → k < scope.length → scope[k]? = full[h - (scope.length - k)]?

/-- The bytes `wildcard_covers` checks are what `IsWildcardOf` says. -/
theorem wildcard_bytes_iff (scope full : List Std.U8) :
    IsWildcardOf scope full ↔ WildcardBytes scope full (host full).length := by
  unfold IsWildcardOf WildcardBytes WildcardHead
  constructor
  · rintro ⟨dotted, rfl, starts_with_dot, suffix⟩
    obtain ⟨short, agree⟩ := List.suffix_iff_getElem?.mp suffix
    cases dotted with
    | nil => simp at starts_with_dot
    | cons d rest =>
      simp only [List.head?_cons, Option.some.injEq] at starts_with_dot
      subst starts_with_dot
      simp only [List.length_cons] at *
      refine ⟨⟨by omega, by simp, by simp, by omega⟩, fun k at_least inside => ?_⟩
      obtain ⟨j, rfl⟩ : ∃ j, k = j + 1 := ⟨k - 1, by omega⟩
      have := agree j (by simp; omega)
      rw [host_reads_as_name full _ (by omega)] at this
      simp only [List.getElem?_cons_succ]
      have where_ : (host full).length - (rest.length + 1 + 1 - (j + 1)) =
          j + (host full).length - (rest.length + 1) := by omega
      rw [where_, this]
      simp
  · rintro ⟨⟨two, first, second, fits⟩, agree⟩
    cases scope with
    | nil => simp at two
    | cons s dotted =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at first
      subst first
      refine ⟨dotted, rfl, ?_, ?_⟩
      · cases dotted with
        | nil => simp at two
        | cons d rest => simpa using second
      · refine List.suffix_iff_getElem?.mpr ⟨by simpa using fits, fun j below => ?_⟩
        have := agree (j + 1) (by omega) (by simp; omega)
        simp only [List.getElem?_cons_succ, List.length_cons] at this ⊢
        have where_ : (host full).length - (dotted.length + 1 - (j + 1)) =
            j + (host full).length - dotted.length := by simp at fits; omega
        rw [where_] at this
        rw [host_reads_as_name full _ (by simp at fits; omega), ← this]
        simp [List.getElem?_eq_getElem below]
/-- The loop of `wildcard_covers`: at each turn the flag says that the head is right and that the
bytes of the scope from 1 up to the position `i` are those of the end of the host. -/
theorem wildcard_loop_is (scope full : Slice Std.U8) (h : Std.Usize)
    (host_is : h.val = (host full.val).length) (flag : Bool) (i : Std.Usize)
    (after_star : 1 ≤ i.val)
    (state : flag = true ↔ WildcardHead scope.val h.val ∧ ∀ k, 1 ≤ k → k < i.val →
      k < scope.length → scope.val[k]? = full.val[h.val - (scope.length - k)]?)
    (read : flag = true → i.val ≤ scope.length) :
    wildcard_covers_loop scope full h flag i ⦃ r =>
      r = true ↔ WildcardBytes scope.val full.val h.val ⦄ := by
  unfold wildcard_covers_loop
  apply loop.spec_decr_nat (fun q => scope.length - q.2.val)
    (fun q => 1 ≤ q.2.val ∧ (q.1 = true → q.2.val ≤ scope.length) ∧
      (q.1 = true ↔ WildcardHead scope.val h.val ∧ ∀ k, 1 ≤ k → k < q.2.val →
        k < scope.length → scope.val[k]? = full.val[h.val - (scope.length - k)]?))
  · rintro ⟨flag, i⟩ ⟨after_star, read, state⟩
    simp only at after_star read state ⊢
    unfold wildcard_covers_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i going below
        obtain ⟨head, agree⟩ := state.mp going
        obtain ⟨two, starts_with_star, starts_with_dot, fits⟩ := head
        have inside : i.val < scope.length := by scalar_tac
        have host_short : h.val ≤ full.length := by
          have begins : host full.val <+: full.val := List.takeWhile_prefix _
          simpa [Slice.length, host_is] using begins.length_le
        -- the byte of the scope at `i`, then how far it is from the end of the scope, and the
        -- byte of the name that many places before the end of the host
        step as ⟨ y, hy ⟩
        step as ⟨ behind, h_behind ⟩
        step as ⟨ place, h_place ⟩
        step as ⟨ z, hz ⟩
        step as ⟨ next, hnext ⟩
        have y_is : scope.val[i.val]? = some y := by simp [hy]
        have z_is : full.val[h.val - (scope.length - i.val)]? = some z := by
          simp only [Usize.ofNatCore, UScalar.ofNatCore_val_eq] at h_behind
          rw [← h_behind, ← h_place]
          simp [hz]
        refine ⟨by omega, fun _ => by omega, ?_, by omega⟩
        rw [decide_eq_true_iff]
        constructor
        · intro same_byte
          refine ⟨⟨two, starts_with_star, starts_with_dot, fits⟩,
            fun k at_least before inside_k => ?_⟩
          rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : k < i.val + 1) with earlier | at_i
          · exact agree k at_least earlier inside_k
          · rw [at_i, y_is, z_is, same_byte]
        · rintro ⟨_, all⟩
          have := all i.val after_star (by omega) inside
          rw [y_is, z_is] at this
          exact Option.some.inj this
      · rename_i going not_below
        -- the whole scope was compared
        have at_end : i.val = scope.length := by scalar_tac
        have same_length : scope.length = scope.val.length := rfl
        simp only [WP.spec_ok]
        rw [state]
        constructor
        · rintro ⟨head, agree⟩
          exact ⟨head, fun k at_least inside => agree k at_least (by omega) inside⟩
        · rintro ⟨head, agree⟩
          exact ⟨head, fun k at_least before inside => agree k at_least inside⟩
    · rename_i stopped
      -- a difference was found, or the head is wrong
      simp only [WP.spec_ok]
      have not_flag : flag = false := by simpa using stopped
      rw [not_flag]
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨head, agree⟩
      have := state.mpr ⟨head, fun k at_least _ inside => agree k at_least inside⟩
      rw [not_flag] at this
      cases this
  · exact ⟨after_star, read, state⟩
/-- `wildcard_covers` says whether the scope is `*.suffix` and the host of the name ends with
`.suffix`. -/
@[step]
theorem wildcard_covers_is (scope full : Slice Std.U8) :
    wildcard_covers scope full ⦃ r => r = true ↔ IsWildcardOf scope.val full.val ⦄ := by
  unfold wildcard_covers
  step as ⟨ h, host_is ⟩
  -- the head of the scope: `*.`, and not longer than the host
  refine WP.spec_bind (Pₘ := fun flag => flag = true ↔ WildcardHead scope.val h.val) ?_
    (fun flag head => ?_)
  · dsimp only [Slice.len]
    split
    · rename_i two
      have two : 2 ≤ scope.length := by
        simpa [Usize.ofNatCore, Slice.length] using (UScalar.le_equiv _ _).mp two
      step as ⟨ first, hfirst ⟩
      have first_is : scope.val[0]? = some first := by simp [hfirst]
      by_cases is_star : first = 42#u8
      · simp only [is_star, ↓reduceIte]
        step as ⟨ second, hsecond ⟩
        have second_is : scope.val[1]? = some second := by simp [hsecond]
        by_cases is_dot : second = 46#u8
        · simp only [is_dot, ↓reduceIte]
          step as ⟨ rest, hrest ⟩
          rw [decide_eq_true_iff, UScalar.le_equiv]
          simp only [Usize.ofNatCore, UScalar.ofNatCore_val_eq] at hrest
          simp only [WildcardHead, first_is, second_is, is_star, is_dot, star, dot]
          simp only [Slice.length] at two
          constructor
          · intro fits
            exact ⟨two, trivial, trivial, by omega⟩
          · rintro ⟨_, _, _, fits⟩
            omega
        · -- the second byte is not `.`
          simp only [is_dot, ↓reduceIte, WP.spec_ok, Bool.false_eq_true, false_iff]
          rintro ⟨_, _, second_dot, _⟩
          rw [second_is] at second_dot
          exact is_dot (Option.some.inj second_dot)
      · -- the first byte is not `*`
        simp only [is_star, ↓reduceIte, WP.spec_ok, Bool.false_eq_true, false_iff]
        rintro ⟨_, first_star, _⟩
        rw [first_is] at first_star
        exact is_star (Option.some.inj first_star)
    · rename_i short
      simp only [WP.spec_ok, Bool.false_eq_true, false_iff, WildcardHead]
      simp only [GE.ge, UScalar.le_equiv, Usize.ofNatCore, UScalar.ofNatCore_val_eq] at short
      exact fun head => short head.1
  · rw [wildcard_bytes_iff, ← host_is]
    apply wildcard_loop_is scope full h host_is flag 1#usize (by simp)
    · -- before the first byte after the `*`, there is nothing to compare
      rw [head]
      exact ⟨fun right_head => ⟨right_head, fun k at_least before _ => by simp at before; omega⟩,
        fun checked => checked.1⟩
    · intro flag_true
      have := (head.mp flag_true).1
      simp only [Slice.length]
      simp
      omega
end PolicyCore
