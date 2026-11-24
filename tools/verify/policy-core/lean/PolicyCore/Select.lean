-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `class` (how specifically a scope applies to an image) and `select` (the
-- scope that applies best): the first is `classOf` of Spec.lean, the second is `Chosen`.
--
-- Why it is needed: the loop of `select` keeps the best scope seen so far with its class and
-- its length; the invariant `Found` says that it applies, that no scope before the position
-- beats it, and that it beats each scope before it.  Two lemmas say what the invariant becomes
-- when the next scope does not beat it (`found_keeps`) and when it does (`found_replaced`).
--
-- Read before this file: Spec.lean, Wildcard.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Wildcard
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

section ClassOf
variable (scope : List Std.U8) (image : Ref)

/-- An exact reference is of class 4. -/
theorem class_of_reference (reference : IsReferenceOf scope image) : classOf scope image = 4 := by
  simp only [classOf, eq_true reference, ↓reduceIte]

/-- A name, namespace or host (not an exact reference) is of class 3. -/
theorem class_of_name (not_reference : ¬ IsReferenceOf scope image)
    (covers : scope ≠ [] ∧ CoversName scope image.name.val) : classOf scope image = 3 := by
  simp only [classOf, eq_false not_reference, eq_true covers, ↓reduceIte]

/-- A wildcard (that is nothing before) is of class 2. -/
theorem class_of_wildcard (not_reference : ¬ IsReferenceOf scope image)
    (not_name : ¬ (scope ≠ [] ∧ CoversName scope image.name.val))
    (wildcard : IsWildcardOf scope image.name.val) : classOf scope image = 2 := by
  simp only [classOf, eq_false not_reference, eq_false not_name, eq_true wildcard, ↓reduceIte]

/-- The empty scope (that is nothing before) is of class 1. -/
theorem class_of_default (not_reference : ¬ IsReferenceOf scope image)
    (not_wildcard : ¬ IsWildcardOf scope image.name.val) (empty : scope = []) :
    classOf scope image = 1 := by
  have not_name : ¬ (scope ≠ [] ∧ CoversName scope image.name.val) := fun named => named.1 empty
  simp only [classOf, eq_false not_reference, eq_false not_name, eq_false not_wildcard,
    eq_true empty, ↓reduceIte]

/-- Any other scope is of class 0. -/
theorem class_of_none (not_reference : ¬ IsReferenceOf scope image)
    (not_name : ¬ (scope ≠ [] ∧ CoversName scope image.name.val))
    (not_wildcard : ¬ IsWildcardOf scope image.name.val) (not_empty : scope ≠ []) :
    classOf scope image = 0 := by
  simp only [classOf, eq_false not_reference, eq_false not_name, eq_false not_wildcard,
    eq_false not_empty, ↓reduceIte]

end ClassOf

/-- `class` is the class of the scope. -/
@[step]
theorem class_is (scope : Slice Std.U8) (image : Ref) :
    «class» scope image ⦃ r => r.val = classOf scope.val image ⦄ := by
  unfold «class»
  step as ⟨ is_ref, h_ref ⟩
  by_cases reference : is_ref = true
  · simp only [reference, ↓reduceIte, WP.spec_ok]
    rw [class_of_reference _ _ (h_ref.mp reference)]
    rfl
  · have not_reference : ¬ IsReferenceOf scope.val image := fun r => reference (h_ref.mpr r)
    simp only [reference, Bool.false_eq_true, ↓reduceIte]
    step as ⟨ empty, h_empty ⟩
    by_cases is_empty : empty = true
    · -- the empty scope: no wildcard, so the scope of the transport
      have scope_nil : scope.val = [] := by
        have : scope.length = 0 := by simpa [is_empty] using h_empty
        simpa [Slice.length] using this
      simp only [is_empty, ↓reduceIte]
      step as ⟨ wildcard, h_wildcard ⟩
      simp only [deref_val] at h_wildcard
      have no_wildcard : ¬ wildcard = true := by
        intro w
        obtain ⟨_, nil_is_cons, _⟩ := h_wildcard.mp w
        simp [scope_nil] at nil_is_cons
      simp only [no_wildcard, Bool.false_eq_true, ↓reduceIte]
      simp only [WP.spec_ok]
      rw [class_of_default _ _ not_reference (fun w => no_wildcard (h_wildcard.mpr w)) scope_nil]
      rfl
    · -- a scope that is not empty: a name, then a wildcard
      have not_nil : scope.val ≠ [] := fun nil =>
        is_empty (h_empty.mpr (by simp [Slice.length, nil]))
      simp only [is_empty, Bool.false_eq_true, ↓reduceIte]
      step as ⟨ named, h_named ⟩
      simp only [deref_val] at h_named
      by_cases covered : named = true
      · simp only [covered, ↓reduceIte, WP.spec_ok]
        rw [class_of_name _ _ not_reference ⟨not_nil, h_named.mp covered⟩]
        rfl
      · have not_name : ¬ (scope.val ≠ [] ∧ CoversName scope.val image.name.val) :=
          fun ⟨_, c⟩ => covered (h_named.mpr c)
        simp only [covered, Bool.false_eq_true, ↓reduceIte]
        step as ⟨ wildcard, h_wildcard ⟩
        simp only [deref_val] at h_wildcard
        by_cases is_wildcard : wildcard = true
        · simp only [is_wildcard, ↓reduceIte, WP.spec_ok]
          rw [class_of_wildcard _ _ not_reference not_name (h_wildcard.mp is_wildcard)]
          rfl
        · simp only [is_wildcard, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
          rw [class_of_none _ _ not_reference not_name (fun w => is_wildcard (h_wildcard.mpr w))
            not_nil]
          rfl
/-- What the loop of `select` has found among the scopes before the position `i`: nothing
(and none of them applies) or the scope `j`, which applies, which no scope before beats, and which
beats each scope before it. -/
def Found (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref) (i : Nat)
    (best : Option Std.Usize) (best_class : Std.U8) (best_len : Std.Usize) : Prop :=
  match best with
  | none => best_class.val = 0 ∧ best_len.val = 0 ∧
      ∀ k < i, ∀ t, scopes.val[k]? = some t → classOf t.val image = 0
  | some j => j.val < i ∧ ∃ s, scopes.val[j.val]? = some s ∧ best_class.val = classOf s.val image ∧
      best_len.val = s.val.length ∧ 0 < best_class.val ∧
      (∀ k < i, ∀ t, scopes.val[k]? = some t → ¬ MoreSpecific image t s) ∧
      (∀ k < j.val, ∀ t, scopes.val[k]? = some t → MoreSpecific image s t)

/-- When every scope was looked at, what was found is what `select` answers. -/
theorem found_is_chosen (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref)
    (best : Option Std.Usize) (best_class : Std.U8) (best_len : Std.Usize)
    (found : Found scopes image scopes.length best best_class best_len) :
    Chosen scopes.val image best := by
  unfold Found at found
  cases best with
  | none =>
    obtain ⟨_, _, all_zero⟩ := found
    intro t listed
    obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp listed
    exact all_zero k (by simpa [Slice.length] using (List.getElem?_eq_some_iff.mp k_at).1) t k_at
  | some j =>
    obtain ⟨_, s, s_at, class_is, _, positive, nobody, first⟩ := found
    refine ⟨s, s_at, by omega, fun t listed => ?_, first⟩
    obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp listed
    exact nobody k (by simpa [Slice.length] using (List.getElem?_eq_some_iff.mp k_at).1) t k_at

/-- A scope that does not beat the best so far (or that applies to nothing) leaves what was found
as it is. -/
theorem found_keeps (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref) (i : Nat)
    (best : Option Std.Usize) (best_class : Std.U8) (best_len : Std.Usize)
    (found : Found scopes image i best best_class best_len)
    (t : alloc.vec.Vec Std.U8) (t_at : scopes.val[i]? = some t)
    (not_better : ¬ (0 < classOf t.val image ∧ (best_class.val < classOf t.val image ∨
      (best_class.val = classOf t.val image ∧ best_len.val < t.val.length)))) :
    Found scopes image (i + 1) best best_class best_len := by
  unfold Found at found ⊢
  cases best with
  | none =>
    obtain ⟨no_class, no_len, all_zero⟩ := found
    refine ⟨no_class, no_len, fun k below u u_at => ?_⟩
    rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
    · exact all_zero k earlier u u_at
    · rw [at_i, t_at] at u_at
      cases Option.some.inj u_at
      omega
  | some j =>
    obtain ⟨before_i, s, s_at, class_is, len_is, positive, nobody, first⟩ := found
    refine ⟨by omega, s, s_at, class_is, len_is, positive, fun k below u u_at => ?_, first⟩
    rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
    · exact nobody k earlier u u_at
    · rw [at_i, t_at] at u_at
      cases Option.some.inj u_at
      unfold MoreSpecific
      omega

/-- A scope that beats the best so far (and applies) becomes the best. -/
theorem found_replaced (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref) (i : Std.Usize)
    (best : Option Std.Usize) (best_class : Std.U8) (best_len : Std.Usize)
    (found : Found scopes image i.val best best_class best_len)
    (t : alloc.vec.Vec Std.U8) (t_at : scopes.val[i.val]? = some t)
    (c : Std.U8) (c_is : c.val = classOf t.val image) (len : Std.Usize)
    (len_is : len.val = t.val.length)
    (better : 0 < classOf t.val image ∧ (best_class.val < classOf t.val image ∨
      (best_class.val = classOf t.val image ∧ best_len.val < t.val.length))) :
    Found scopes image (i.val + 1) (some i) c len := by
  -- every scope before `t` is beaten by it
  have beats_all : ∀ k < i.val, ∀ u, scopes.val[k]? = some u → MoreSpecific image t u := by
    intro k earlier u u_at
    unfold MoreSpecific
    cases best with
    | none =>
      obtain ⟨no_class, _, all_zero⟩ := found
      have := all_zero k earlier u u_at
      omega
    | some j =>
      obtain ⟨_, s, _, class_is, len_is, _, nobody, _⟩ := found
      have := nobody k earlier u u_at
      unfold MoreSpecific at this
      omega
  refine ⟨by omega, t, t_at, c_is, len_is, by omega, fun k below u u_at => ?_,
    beats_all⟩
  rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
  · have := beats_all k earlier u u_at
    unfold MoreSpecific at this ⊢
    omega
  · rw [at_i, t_at] at u_at
    cases Option.some.inj u_at
    unfold MoreSpecific
    omega

/-- The loop of `select`: starting from what is found before the position `i`, it returns the
answer `Chosen`. -/
theorem select_loop_is (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref)
    (best : Option Std.Usize) (best_class : Std.U8) (best_len : Std.Usize) (i : Std.Usize)
    (read : i.val ≤ scopes.length) (found : Found scopes image i.val best best_class best_len) :
    select_loop scopes image best best_class best_len i ⦃ r => Chosen scopes.val image r ⦄ := by
  unfold select_loop
  apply loop.spec_decr_nat (fun q => scopes.length - q.2.2.2.val)
    (fun q => q.2.2.2.val ≤ scopes.length ∧
      Found scopes image q.2.2.2.val q.1 q.2.1 q.2.2.1)
  · rintro ⟨best, best_class, best_len, i⟩ ⟨read, found⟩
    simp only at read found ⊢
    unfold select_loop.body
    dsimp only [Slice.len]
    split
    · rename_i below
      have inside : i.val < scopes.length := by scalar_tac
      -- the scope `i` is read and its class computed
      step as ⟨ v, hv ⟩
      have v_at : scopes.val[i.val]? = some v := by simp [hv]
      step as ⟨ c, hc ⟩
      simp only [deref_val] at hc
      have len_is : v.len.val = v.val.length := by simp [alloc.vec.Vec.len]
      -- it becomes the best if it applies and beats the best so far (a higher class, or the
      -- same class and a longer scope); otherwise what was found stays
      refine WP.spec_bind (Pₘ := fun r : Option Std.Usize × Std.U8 × Std.Usize =>
        Found scopes image (i.val + 1) r.1 r.2.1 r.2.2) ?_ (fun r kept => ?_)
      · by_cases applies : c > 0#u8
        · simp only [eq_true applies, ↓reduceIte]
          by_cases higher : c > best_class
          · simp only [eq_true higher, ↓reduceIte]
            refine (WP.spec_ok _).mpr (found_replaced scopes image i best best_class best_len
              found v v_at c hc v.len len_is ⟨?_, Or.inl ?_⟩)
            · simp only [GT.gt, UScalar.lt_equiv] at applies; simpa [hc] using applies
            · simp only [GT.gt, UScalar.lt_equiv] at higher; omega
          · by_cases same_class : c = best_class
            · by_cases longer : v.len > best_len
              · simp only [eq_false higher, eq_true same_class, eq_true longer, ↓reduceIte]
                refine (WP.spec_ok _).mpr (found_replaced scopes image i best best_class best_len
                  found v v_at c hc v.len len_is ⟨?_, Or.inr ⟨?_, ?_⟩⟩)
                · simp only [GT.gt, UScalar.lt_equiv] at applies; simpa [hc] using applies
                · rw [← hc, same_class]
                · simp only [GT.gt, UScalar.lt_equiv] at longer; omega
              · simp only [eq_false higher, eq_true same_class, eq_false longer, ↓reduceIte]
                refine (WP.spec_ok _).mpr (found_keeps scopes image i.val best best_class best_len
                  found v v_at ?_)
                simp only [GT.gt, UScalar.lt_equiv] at longer
                rw [UScalar.eq_equiv] at same_class
                omega
            · simp only [eq_false higher, eq_false same_class, ↓reduceIte]
              refine (WP.spec_ok _).mpr (found_keeps scopes image i.val best best_class best_len
                found v v_at ?_)
              simp only [GT.gt, UScalar.lt_equiv] at higher
              rw [UScalar.eq_equiv] at same_class
              omega
        · simp only [eq_false applies, ↓reduceIte]
          refine (WP.spec_ok _).mpr (found_keeps scopes image i.val best best_class best_len
            found v v_at ?_)
          simp [GT.gt, UScalar.lt_equiv] at applies
          omega
      · obtain ⟨best1, best_class1, best_len1⟩ := r
        step as ⟨ next, hnext ⟩
        exact ⟨by omega, by simpa [hnext] using kept, by omega⟩
    · rename_i past_end
      -- every scope was looked at
      have at_end : i.val = scopes.length := by scalar_tac
      simp only [WP.spec_ok]
      rw [at_end] at found
      exact found_is_chosen scopes image best best_class best_len found
  · exact ⟨read, found⟩
/-- `select` chooses the most specific scope that applies. -/
theorem select_is (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref) :
    select scopes image ⦃ r => Chosen scopes.val image r ⦄ := by
  unfold select
  apply select_loop_is
  · simp
  · exact ⟨rfl, rfl, fun k below => by simp at below⟩
end PolicyCore
