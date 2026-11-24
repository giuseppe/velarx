-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `precheck` answers: it accepts, or leaves the decision to the
-- signatures, or refuses, as a function of the kinds of the requirements and the mode only.
--
-- Why it is needed: `precheck` is what the shell asks before it reads any signature; the claims
-- say that `decide` then keeps its answer (Claims.lean).  The invariant `Checked` of its loop says
-- what is known of the requirements before the position it is at.
--
-- Read before this file: Spec.lean, Decide.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Decide
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- `is_signed` says whether the requirement asks for a signature. -/
@[step]
theorem is_signed_is (item : Item) :
    is_signed item ⦃ b => b = true ↔ IsSignatureRequirement item ⦄ := by
  unfold is_signed
  cases item <;> simp [IsSignatureRequirement]

/-- What the loop of `precheck` knows after the requirements before the position `i`: no
refusal so far exactly when none of them refuses by its kind, and then `needs` says whether one
of them asks for a signature. -/
def Checked (mode : Mode) (items : Slice Item) (i : Nat)
    (refused : Option (Std.Usize × Why)) (needs : Bool) : Prop :=
  (refused = none ↔ ∀ k < i, ∀ item, items.val[k]? = some item → ¬ RefusesByKind mode item) ∧
  (refused = none → (needs = true ↔ ∃ k < i, ∃ item, items.val[k]? = some item ∧
    IsSignatureRequirement item))

/-- A requirement that does not refuse by its kind extends what has been checked by one. -/
theorem checked_next_ok (mode : Mode) (items : Slice Item) (i : Nat) (needs needs' : Bool)
    (checked : Checked mode items i none needs) (item : Item) (item_at : items.val[i]? = some item)
    (no_kind : ¬ RefusesByKind mode item)
    (needs_is : needs' = true ↔ (needs = true ∨ IsSignatureRequirement item)) :
    Checked mode items (i + 1) none needs' := by
  obtain ⟨nothing_refused, needs_iff⟩ := checked
  refine ⟨⟨fun _ k below u u_at => ?_, fun _ => rfl⟩, fun _ => ?_⟩
  · rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
    · exact nothing_refused.mp rfl k earlier u u_at
    · rw [at_i, item_at] at u_at
      cases Option.some.inj u_at
      exact no_kind
  · rw [needs_is, needs_iff rfl]
    constructor
    · rintro (⟨k, earlier, found⟩ | is_signature)
      · exact ⟨k, by omega, found⟩
      · exact ⟨i, by omega, item, item_at, is_signature⟩
    · rintro ⟨k, below, u, u_at, is_signature⟩
      rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
      · exact Or.inl ⟨k, earlier, u, u_at, is_signature⟩
      · rw [at_i, item_at] at u_at
        cases Option.some.inj u_at
        exact Or.inr is_signature

/-- A requirement that refuses by its kind stops the check: the refusal is kept. -/
theorem checked_next_refused (mode : Mode) (items : Slice Item) (i : Nat) (needs' : Bool)
    (item : Item) (item_at : items.val[i]? = some item) (kind : RefusesByKind mode item)
    (refusal : Std.Usize × Why) :
    Checked mode items (i + 1) (some refusal) needs' := by
  refine ⟨⟨fun impossible => by simp at impossible, fun all => ?_⟩,
    fun impossible => by simp at impossible⟩
  exact (all i (by omega) item item_at kind).elim

/-- The loop of `precheck`, when it stops: it has checked every requirement (or has refused). -/
theorem precheck_loop_is (mode : Mode) (items : Slice Item)
    (refused : Option (Std.Usize × Why)) (needs : Bool) (i : Std.Usize)
    (read : i.val ≤ items.length) (checked : Checked mode items i.val refused needs) :
    precheck_loop mode items refused needs i ⦃ r =>
      Checked mode items items.length r.1 r.2 ⦄ := by
  unfold precheck_loop
  apply loop.spec_decr_nat (fun q => items.length - q.2.2.val)
    (fun q => q.2.2.val ≤ items.length ∧ Checked mode items q.2.2.val q.1 q.2.1)
  · rintro ⟨refused, needs, i⟩ ⟨read, checked⟩
    simp only at read checked ⊢
    unfold precheck_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i below still_going
        have inside : i.val < items.length := by scalar_tac
        obtain rfl : refused = none := by simpa using still_going
        step as ⟨ item, h_item ⟩
        have item_at : items.val[i.val]? = some item := by simp [h_item]
        step as ⟨ refusal, h_refusal ⟩
        -- the refusal by kind, then whether the requirement asks for a signature, then one
        -- position on
        cases refusal with
        | none =>
          have no_kind : ¬ RefusesByKind mode item := fun kind => by
            simpa using h_refusal.mpr kind
          simp only [Std.bind_ok]
          step as ⟨ signed, h_signed ⟩
          by_cases is_signature : signed = true
          · simp only [is_signature, ↓reduceIte, Std.bind_ok]
            step as ⟨ next, hnext ⟩
            have checked_next := checked_next_ok mode items i.val needs true checked item
              item_at no_kind ⟨fun _ => Or.inr (h_signed.mp is_signature), fun _ => rfl⟩
            exact ⟨by omega, by simpa [hnext] using checked_next, by omega⟩
          · simp only [is_signature, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
            step as ⟨ next, hnext ⟩
            have checked_next := checked_next_ok mode items i.val needs needs checked item
              item_at no_kind ⟨Or.inl, fun h => h.elim id fun sig =>
                absurd (h_signed.mpr sig) is_signature⟩
            exact ⟨by omega, by simpa [hnext] using checked_next, by omega⟩
        | some why =>
          have kind : RefusesByKind mode item := h_refusal.mp rfl
          simp only [Std.bind_ok]
          step as ⟨ signed, h_signed ⟩
          by_cases is_signature : signed = true
          · simp only [is_signature, ↓reduceIte, Std.bind_ok]
            step as ⟨ next, hnext ⟩
            have checked_next := checked_next_refused mode items i.val true item item_at kind
              (i, why)
            exact ⟨by omega, by simpa [hnext] using checked_next, by omega⟩
          · simp only [is_signature, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
            step as ⟨ next, hnext ⟩
            have checked_next := checked_next_refused mode items i.val needs item item_at kind
              (i, why)
            exact ⟨by omega, by simpa [hnext] using checked_next, by omega⟩
      · rename_i below stopped
        -- a requirement refused: the check stopped
        have refusal : ¬ refused = none := by simpa using stopped
        obtain ⟨nothing_refused, _⟩ := checked
        have stopped_checking : Checked mode items items.length refused needs :=
          ⟨⟨fun is_none => (refusal is_none).elim, fun all => (refusal
            (nothing_refused.mpr fun k before u u_at => all k (by omega) u u_at)).elim⟩,
            fun is_none => (refusal is_none).elim⟩
        exact (WP.spec_ok _).mpr stopped_checking
    · rename_i past_end
      -- every requirement was checked
      have at_end : i.val = items.length := by scalar_tac
      rw [at_end] at checked
      exact (WP.spec_ok _).mpr checked
  · exact ⟨read, checked⟩
/-- `precheck` accepts when there is a requirement, none refuses by its kind, none asks for a
signature and the mode does not ask for one; it says the signatures decide when there is a
requirement, none refuses by its kind and one asks for a signature; it refuses otherwise. -/
theorem precheck_is (mode : Mode) (items : Slice Item) :
    precheck mode items ⦃ p =>
      (p = Pre.Accept ↔ items.val ≠ [] ∧ (∀ item ∈ items.val, ¬ RefusesByKind mode item) ∧
        (∀ item ∈ items.val, ¬ IsSignatureRequirement item) ∧ mode ≠ Mode.MustBeSigned) ∧
      (p = Pre.NeedsSignatures ↔ items.val ≠ [] ∧ (∀ item ∈ items.val, ¬ RefusesByKind mode item) ∧
        ∃ item ∈ items.val, IsSignatureRequirement item) ⦄ := by
  unfold precheck
  refine WP.spec_bind (precheck_loop_is mode items none false 0#usize (by simp)
    ⟨⟨fun _ k below => by simp at below, fun _ => rfl⟩,
      fun _ => by simp⟩) (fun r checked => ?_)
  obtain ⟨refused, needs⟩ := r
  obtain ⟨nothing_refused, needs_iff⟩ := checked
  simp only [all_listed] at nothing_refused
  simp only [some_listed] at needs_iff
  step as ⟨ empty, h_empty ⟩
  have empty_iff : empty = true ↔ items.val = [] := by
    rw [h_empty]
    simp [Slice.length]
  by_cases no_requirement : empty = true
  · -- no requirement at all: refused
    simp only [no_requirement, ↓reduceIte, WP.spec_ok]
    simp [empty_iff.mp no_requirement]
  · have not_nil : items.val ≠ [] := fun nil => no_requirement (empty_iff.mpr nil)
    simp only [no_requirement, Bool.false_eq_true, ↓reduceIte]
    cases refused with
    | some refusal =>
      -- a requirement refuses by its kind
      obtain ⟨at_, why⟩ := refusal
      refine (WP.spec_ok _).mpr ⟨⟨fun impossible => (by cases impossible), ?_⟩,
        ⟨fun impossible => (by cases impossible), ?_⟩⟩
      · rintro ⟨_, fine, _⟩
        exact absurd (nothing_refused.mpr fine) (by simp)
      · rintro ⟨_, fine, _⟩
        exact absurd (nothing_refused.mpr fine) (by simp)
    | none =>
      have fine := nothing_refused.mp rfl
      have needs_signature := needs_iff rfl
      refine WP.spec_bind (Pₘ := fun b => b = true ↔ mode = Mode.MustBeSigned) ?_
        (fun must must_iff => ?_)
      · exact must_be_signed_is mode
      by_cases is_must : must = true
      · have mode_is := must_iff.mp is_must
        simp only [is_must, ↓reduceIte]
        by_cases asks : needs = true
        · simp only [asks, ↓reduceIte]
          have some_signature := needs_signature.mp asks
          refine (WP.spec_ok _).mpr ⟨⟨fun impossible => (by cases impossible),
            fun ⟨_, _, _, not_must⟩ => (not_must mode_is).elim⟩,
            ⟨fun _ => ⟨not_nil, fine, some_signature⟩, fun _ => rfl⟩⟩
        · simp only [asks, Bool.false_eq_true, ↓reduceIte]
          refine (WP.spec_ok _).mpr ⟨⟨fun impossible => (by cases impossible),
            fun ⟨_, _, _, not_must⟩ => (not_must mode_is).elim⟩,
            ⟨fun impossible => (by cases impossible),
            fun ⟨_, _, some_signature⟩ => (asks (needs_signature.mpr some_signature)).elim⟩⟩
      · simp only [is_must, Bool.false_eq_true, ↓reduceIte]
        by_cases asks : needs = true
        · simp only [asks, ↓reduceIte]
          have some_signature := needs_signature.mp asks
          obtain ⟨item, listed, is_signature⟩ := some_signature
          refine (WP.spec_ok _).mpr ⟨⟨fun impossible => (by cases impossible),
            fun ⟨_, _, none_sign, _⟩ => (none_sign item listed is_signature).elim⟩,
            ⟨fun _ => ⟨not_nil, fine, item, listed, is_signature⟩, fun _ => rfl⟩⟩
        · simp only [asks, Bool.false_eq_true, ↓reduceIte]
          refine (WP.spec_ok _).mpr ⟨⟨fun _ => ⟨not_nil, fine, fun item listed is_signature =>
              asks (needs_signature.mpr ⟨item, listed, is_signature⟩),
              fun is_mode => is_must (must_iff.mpr is_mode)⟩, fun _ => rfl⟩,
            ⟨fun impossible => (by cases impossible),
              fun ⟨_, _, some_signature⟩ => (asks (needs_signature.mpr some_signature)).elim⟩⟩
end PolicyCore
