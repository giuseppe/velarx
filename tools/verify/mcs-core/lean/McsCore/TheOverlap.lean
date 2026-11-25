-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `contains` and `overlap`, which compare two levels by their sets of
--    categories.
-- Why it is needed: the allocator uses them to keep a fresh level away from the levels in use.
-- Read before this file: TheParse.lean.
-- Notation: `Reach a b` and `Covers outer inner` are in Spec.lean.
import McsCore.TheParse
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- What `contains` answers: it returns, and it is true exactly when both texts are levels, the
inner one has a category, and its categories are all in the outer one. -/
theorem contains_spec (outer inner : Slice Std.U8) :
    contains outer inner ⦃ b => b = true ↔
      ∃ S T, Level outer.val S ∧ Level inner.val T ∧ (∃ c, T c) ∧ ∀ c, T c → S c ⦄ := by
  unfold contains
  step with parse_spec outer as ⟨ po, co1, so1 ⟩
  step with parse_spec inner as ⟨ pi, co2, so2 ⟩
  cases po with
  | none =>
    refine (WP.spec_ok _).mpr ?_
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨S, T, lo, li, _⟩
    obtain ⟨c, hc, _⟩ := co1 S lo
    simp at hc
  | some o =>
    cases pi with
    | none =>
      refine (WP.spec_ok _).mpr ?_
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨S, T, lo, li, _⟩
      obtain ⟨c, hc, _⟩ := co2 T li
      simp at hc
    | some i =>
      dsimp only
      step with is_empty_spec i as ⟨ e, he ⟩
      obtain ⟨S, lS, mS⟩ := so1 o rfl
      obtain ⟨T, lT, mT⟩ := so2 i rfl
      by_cases empty : e = true
      · simp only [empty, ite_true]
        refine (WP.spec_ok _).mpr ?_
        simp only [Bool.false_eq_true, false_iff]
        rintro ⟨S', T', lo, li, ⟨c, hc⟩, _⟩
        obtain ⟨c1, h1, m1⟩ := co2 T' li
        have : i = c1 := Option.some.inj h1
        subst this
        exact he.mp empty c ((m1 c).mpr hc)
      · simp only [empty, Bool.false_eq_true, ite_false]
        step with within_spec i o as ⟨ w, hw ⟩
        refine ⟨fun h => ?_, fun ⟨S', T', lo, li, ⟨c, hc⟩, sub⟩ => ?_⟩
        · refine ⟨S, T, lS, lT, ?_, fun c hc => (mS c).mp (hw.mp h c ((mT c).mpr hc))⟩
          by_contra none
          exact empty (he.mpr (fun c m => none ⟨c, (mT c).mp m⟩))
        · obtain ⟨c1, h1, m1⟩ := co1 S' lo
          obtain ⟨c2, h2, m2⟩ := co2 T' li
          have e1 : o = c1 := Option.some.inj h1
          have e2 : i = c2 := Option.some.inj h2
          subst e1; subst e2
          apply hw.mpr
          intro d hd
          exact (m1 d).mpr (sub d ((m2 d).mp hd))

/-- What `overlap` answers: it returns, and it is true exactly when one text is no level, or both
are levels with categories and the categories of one are all in the other. -/
theorem overlap_spec (a b : Slice Std.U8) :
    overlap a b ⦃ r => r = true ↔
      (¬ (∃ S, Level a.val S) ∨ ¬ (∃ T, Level b.val T)) ∨
      ∃ S T, Level a.val S ∧ Level b.val T ∧ (∃ c, S c) ∧ (∃ c, T c) ∧
        ((∀ c, S c → T c) ∨ (∀ c, T c → S c)) ⦄ := by
  unfold overlap
  step with parse_spec a as ⟨ pa, ca1, sa1 ⟩
  step with parse_spec b as ⟨ pb, cb1, sb1 ⟩
  cases pa with
  | none =>
    refine (WP.spec_ok _).mpr ?_
    simp only [true_iff]
    exact Or.inl (Or.inl (fun ⟨S, lS⟩ => by
      obtain ⟨c, hc, _⟩ := ca1 S lS; simp at hc))
  | some x =>
    cases pb with
    | none =>
      refine (WP.spec_ok _).mpr ?_
      simp only [true_iff]
      exact Or.inl (Or.inr (fun ⟨T, lT⟩ => by
        obtain ⟨c, hc, _⟩ := cb1 T lT; simp at hc))
    | some y =>
      dsimp only
      obtain ⟨S, lS, mS⟩ := sa1 x rfl
      obtain ⟨T, lT, mT⟩ := sb1 y rfl
      have back : ∀ S' T', Level a.val S' → Level b.val T' → (∀ c, Mem x c ↔ S' c) ∧ (∀ c, Mem y c ↔ T' c) := by
        intro S' T' la lb
        obtain ⟨c1, h1, m1⟩ := ca1 S' la
        obtain ⟨c2, h2, m2⟩ := cb1 T' lb
        have e1 : x = c1 := Option.some.inj h1
        have e2 : y = c2 := Option.some.inj h2
        subst e1; subst e2
        exact ⟨m1, m2⟩
      step with is_empty_spec x as ⟨ ex, hex ⟩
      have none_cases : ¬ ((¬ (∃ S, Level a.val S) ∨ ¬ (∃ T, Level b.val T))) := by
        rintro (h | h)
        · exact h ⟨S, lS⟩
        · exact h ⟨T, lT⟩
      by_cases ex_t : ex = true
      · simp only [ex_t, ite_true]
        refine (WP.spec_ok _).mpr ⟨fun h => absurd h (by simp), ?_⟩
        rintro (h | ⟨S', T', la, lb, ⟨c, hc⟩, _⟩)
        · exact absurd h none_cases
        · exact absurd (((back S' T' la lb).1 c).mpr hc) (hex.mp ex_t c)
      · simp only [ex_t, Bool.false_eq_true, ite_false]
        step with is_empty_spec y as ⟨ ey, hey ⟩
        by_cases ey_t : ey = true
        · simp only [ey_t, ite_true]
          refine (WP.spec_ok _).mpr ⟨fun h => absurd h (by simp), ?_⟩
          rintro (h | ⟨S', T', la, lb, _, ⟨c, hc⟩, _⟩)
          · exact absurd h none_cases
          · exact absurd (((back S' T' la lb).2 c).mpr hc) (hey.mp ey_t c)
        · simp only [ey_t, Bool.false_eq_true, ite_false]
          have x_ne : ∃ c, S c := by
            by_contra no
            exact ex_t (hex.mpr (fun c m => no ⟨c, (mS c).mp m⟩))
          have y_ne : ∃ c, T c := by
            by_contra no
            exact ey_t (hey.mpr (fun c m => no ⟨c, (mT c).mp m⟩))
          step with within_spec x y as ⟨ w1, hw1 ⟩
          by_cases w1_t : w1 = true
          · simp only [w1_t, ite_true]
            refine (WP.spec_ok _).mpr ⟨fun _ => ?_, fun _ => rfl⟩
            exact Or.inr ⟨S, T, lS, lT, x_ne, y_ne, Or.inl (fun c hc => (mT c).mp (hw1.mp w1_t c ((mS c).mpr hc)))⟩
          · simp only [w1_t, Bool.false_eq_true, ite_false]
            step with within_spec y x as ⟨ w2, hw2 ⟩
            refine ⟨fun h => ?_, fun h => ?_⟩
            · exact Or.inr ⟨S, T, lS, lT, x_ne, y_ne,
                Or.inr (fun c hc => (mS c).mp (hw2.mp h c ((mT c).mpr hc)))⟩
            · rcases h with h | ⟨S', T', la, lb, _, _, sub⟩
              · exact absurd h none_cases
              · obtain ⟨m1, m2⟩ := back S' T' la lb
                rcases sub with sub | sub
                · exact absurd (hw1.mpr (fun c hc => (m2 c).mpr (sub c ((m1 c).mp hc)))) w1_t
                · exact hw2.mpr (fun c hc => (m1 c).mpr (sub c ((m2 c).mp hc)))

end McsCore
