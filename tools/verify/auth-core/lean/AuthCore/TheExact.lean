-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `exact keys host` answers the first key that is the host alone, the Hub
-- under its one name (`FindsTheHost` of Spec.lean), and none when there is none.  It returns for
-- any list.
-- Why it is needed: the key of a helper (`credHelpers`) is found by it.
-- Read before this file: Spec.lean, Bytes.lean, TheHub.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a Rust
-- function and names its result `x` and what is known of it `hx`; `l[i]?` is `some` of the element
-- at the place `i` of `l`, or `none`.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheHub

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- Making the names of the Hub one is done once: `docker.io` and any other host stay. -/
theorem hub_of_hub_of (host : Bytes) : HubOf (HubOf host) = HubOf host := by
  unfold HubOf
  by_cases h : host = HubIndex ∨ host = HubRegistry
  · have : ¬ (HubName = HubIndex ∨ HubName = HubRegistry) := by decide
    simp [h, this]
  · simp [h]

/-- The loop of **`exact`**: from the key `i`, with the key found so far, it ends with the first key
of all that is the host `h` (the bytes the host is looked for as), or none. -/
theorem exact_loop_finds (keys : Slice (alloc.vec.Vec Std.U8)) (host : Slice Std.U8)
    (h : Bytes) (is_h : host.val = h) (hub : HubOf h = h) (found : Option Std.Usize) (i : Std.Usize)
    (inside : i.val ≤ keys.length)
    (found_is : ∀ j, found = some j → j.val < i.val ∧ (keys.val.map (·.val))[j.val]? = some h ∧
      ∀ m k, m < j.val → (keys.val.map (·.val))[m]? = some k → k ≠ h)
    (none_is : found = none → ∀ m k, m < i.val → (keys.val.map (·.val))[m]? = some k → k ≠ h) :
    exact_loop keys host found i ⦃ r =>
      FindsTheHost (keys.val.map (·.val)) h (r.map (·.val)) ⦄ := by
  unfold exact_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => keys.length - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => q.2.val ≤ keys.length ∧
      (∀ j, q.1 = some j → j.val < q.2.val ∧ (keys.val.map (·.val))[j.val]? = some h ∧
        ∀ m k, m < j.val → (keys.val.map (·.val))[m]? = some k → k ≠ h) ∧
      (q.1 = none → ∀ m k, m < q.2.val → (keys.val.map (·.val))[m]? = some k → k ≠ h))
  · rintro ⟨found, i⟩ ⟨inside, found_is, none_is⟩
    simp only at inside found_is none_is ⊢
    unfold exact_loop.body
    have map_len : (keys.val.map (·.val)).length = keys.length := by simp [Slice.length]
    -- when the loop stops, `found` answers
    have stops : ∀ (found : Option Std.Usize) (i : Std.Usize), i.val ≤ keys.length →
        (∀ j, found = some j → j.val < i.val ∧ (keys.val.map (·.val))[j.val]? = some h ∧
          ∀ m k, m < j.val → (keys.val.map (·.val))[m]? = some k → k ≠ h) →
        (found = none → ∀ m k, m < i.val → (keys.val.map (·.val))[m]? = some k → k ≠ h) →
        (found ≠ none ∨ i.val = keys.length) →
        FindsTheHost (keys.val.map (·.val)) h (found.map (·.val)) := by
      intro found i inside found_is none_is done
      refine ⟨fun j hj => ?_, ?_⟩
      · obtain ⟨j', rfl, rfl⟩ : ∃ j', found = some j' ∧ j'.val = j := by
          cases found with
          | none => simp at hj
          | some j' => exact ⟨j', rfl, by simpa using hj⟩
        obtain ⟨_, at_j, before⟩ := found_is j' rfl
        rw [hub]
        exact ⟨at_j, fun m k lt hk => before m k lt hk⟩
      · constructor
        · intro isnone k hk
          rw [Option.map_eq_none_iff] at isnone
          obtain ⟨m, hm⟩ := List.mem_iff_getElem?.mp hk
          have : m < i.val := by
            rcases done with d | d
            · exact absurd isnone d
            · have := (List.getElem?_eq_some_iff.mp hm).1
              omega
          rw [hub]
          exact none_is isnone m k this hm
        · intro all
          by_contra notnone
          cases found with
          | none => exact notnone (by simp)
          | some j' =>
            obtain ⟨_, at_j, _⟩ := found_is j' rfl
            exact all h (List.mem_iff_getElem?.mpr ⟨_, at_j⟩) hub.symm
    by_cases is_none : found = none
    · subst is_none
      simp only [core.option.Option.is_none, Option.isNone_none, ite_true]
      by_cases below : i.val < keys.length
      · have below' : i < Slice.len keys := by scalar_tac
        simp only [below', ite_true]
        step as ⟨ v, is_v ⟩
        step as ⟨ b1, is_b1 ⟩
        have v_at : (keys.val.map (·.val))[i.val]? = some v.val := by
          simp [is_v, List.getElem?_eq_getElem (show i.val < keys.val.length from below)]
        by_cases same : b1 = true
        · simp only [same, ite_true, Std.bind_ok]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
          · intro j hj
            have : j = i := by simpa using hj.symm
            subst this
            refine ⟨by scalar_tac, ?_, fun m k lt hk => none_is rfl m k (by scalar_tac) hk⟩
            have : v.val = h := by simpa [← is_h] using is_b1.mp same
            rw [v_at, this]
          · intro hn; simp at hn
        · simp only [same, Bool.false_eq_true, ite_false, Std.bind_ok]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
          · intro j hj; simp at hj
          · intro _ m k lt hk
            by_cases mi : m < i.val
            · exact none_is rfl m k mi hk
            · have : m = i.val := by omega
              subst this
              rw [v_at] at hk
              have := Option.some.inj hk
              subst this
              intro eq
              apply same
              apply is_b1.mpr
              simpa [← is_h] using eq
      · have below' : ¬ i < Slice.len keys := by scalar_tac
        simp only [below', ite_false]
        refine (WP.spec_ok _).mpr ?_
        exact stops none i inside found_is none_is (Or.inr (by scalar_tac))
    · simp only [core.option.Option.is_none]
      have : ¬ (found = none) := is_none
      simp only [Option.isNone_iff_eq_none, is_none, ite_false]
      refine (WP.spec_ok _).mpr ?_
      exact stops found i inside found_is none_is (Or.inl is_none)
  · exact ⟨inside, found_is, none_is⟩

/-- **`exact`** answers the first key that is the host alone, the Hub under its one name. -/
@[step] theorem exact_finds_the_host (keys : Slice (alloc.vec.Vec Std.U8)) (host : Slice Std.U8) :
    exact keys host ⦃ found =>
      FindsTheHost (keys.val.map (·.val)) host.val (found.map (·.val)) ⦄ := by
  unfold exact
  step as ⟨ host1, is_host1 ⟩
  have hub : HubOf host1.val = host1.val := by rw [is_host1, hub_of_hub_of]
  have := exact_loop_finds keys host1 host1.val rfl hub none 0#usize (by simp)
    (by simp) (by simp)
  simpa [FindsTheHost, is_host1, hub_of_hub_of] using this

end AuthCore
