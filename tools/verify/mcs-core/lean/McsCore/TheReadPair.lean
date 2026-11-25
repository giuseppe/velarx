-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `read_pair`: it answers the pair of a label of the canonical spelling, and
--    only of that spelling.
-- Why it is needed: the stored levels are read back with it.
-- Read before this file: ThePair.lean, TheParse.lean, TheSets.lean.
-- Notation: `read_pair b ⦃ p => ... ⦄`: it returns and its answer `p` satisfies the claim.
import McsCore.ThePair
import McsCore.TheParse
import McsCore.TheSets
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The first loop of `read_pair` finds the first category of the set from a place. -/
theorem read_pair_loop0_spec (cats : Cats) (low : Std.U16) (le : low.val ≤ 1024) :
    read_pair_loop0 cats low ⦃ r => r.val ≤ 1024 ∧ low.val ≤ r.val ∧ (r.val < 1024 → Mem cats r.val) ∧
      ∀ j, low.val ≤ j → j < r.val → ¬ Mem cats j ⦄ := by
  unfold read_pair_loop0
  have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  apply loop_answers (fun x : Std.U16 => read_pair_loop0.body cats x)
    (fun x y => y.val ≤ 1024 ∧ x.val ≤ y.val ∧ (y.val < 1024 → Mem cats y.val) ∧
      ∀ j, x.val ≤ j → j < y.val → ¬ Mem cats j)
    (fun x => 1024 - x.val) (fun x => x.val ≤ 1024)
  · intro x inv
    unfold read_pair_loop0.body
    by_cases below : x < CATEGORIES
    · simp only [below, ite_true]
      have below' : x.val < 1024 := by scalar_tac
      step with has_spec cats x as ⟨ b, hb ⟩
      by_cases found : b = true
      · simp only [found, ite_true]
        refine (WP.spec_ok _).mpr ⟨inv, le_refl _, fun _ => hb.mp found, fun j a b => by omega⟩
      · have hb' : ¬ Mem cats x.val := fun m => found (hb.mpr m)
        simp only [found, Bool.false_eq_true, ite_false]
        step as ⟨ x1, is_x1 ⟩
        refine ⟨by omega, by omega, ?_⟩
        intro y h1 h2 h3 h4
        refine ⟨h1, by omega, h3, ?_⟩
        intro j a b
        rcases Nat.eq_or_lt_of_le a with eq | lt
        · rw [← eq]; exact hb'
        · exact h4 j (by omega) b
    · simp only [below, ite_false]
      have : ¬ x.val < 1024 := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨inv, le_refl _, fun h => absurd h this, fun j a b => by omega⟩
  · exact le

/-- The second loop of `read_pair` finds the first category of the set from a place. -/
theorem read_pair_loop1_spec (cats : Cats) (low : Std.U16) (le : low.val ≤ 1025) :
    read_pair_loop1 cats low ⦃ r => r.val ≤ 1025 ∧ low.val ≤ r.val ∧ (r.val < 1024 → Mem cats r.val) ∧
      ∀ j, low.val ≤ j → j < r.val → ¬ Mem cats j ⦄ := by
  unfold read_pair_loop1
  have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  apply loop_answers (fun x : Std.U16 => read_pair_loop1.body cats x)
    (fun x y => y.val ≤ 1025 ∧ x.val ≤ y.val ∧ (y.val < 1024 → Mem cats y.val) ∧
      ∀ j, x.val ≤ j → j < y.val → ¬ Mem cats j)
    (fun x => 1025 - x.val) (fun x => x.val ≤ 1025)
  · intro x inv
    unfold read_pair_loop1.body
    by_cases below : x < CATEGORIES
    · simp only [below, ite_true]
      have below' : x.val < 1024 := by scalar_tac
      step with has_spec cats x as ⟨ b, hb ⟩
      by_cases found : b = true
      · simp only [found, ite_true]
        refine (WP.spec_ok _).mpr ⟨inv, le_refl _, fun _ => hb.mp found, fun j a b => by omega⟩
      · have hb' : ¬ Mem cats x.val := fun m => found (hb.mpr m)
        simp only [found, Bool.false_eq_true, ite_false]
        step as ⟨ x1, is_x1 ⟩
        refine ⟨by omega, by omega, ?_⟩
        intro y h1 h2 h3 h4
        refine ⟨h1, by omega, h3, ?_⟩
        intro j a b
        rcases Nat.eq_or_lt_of_le a with eq | lt
        · rw [← eq]; exact hb'
        · exact h4 j (by omega) b
    · simp only [below, ite_false]
      have : ¬ x.val < 1024 := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨inv, le_refl _, fun h => absurd h this, fun j a b => by omega⟩
  · exact le

/-- The comparison of two slices of bytes is true exactly when they are equal. -/
theorem slice_eq_spec (s level : Slice Std.U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 s level ⦃ b => b = true ↔ s.val = level.val ⦄ := by
  refine WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8 s level ?_) ?_
  · intro x y
    simp [core.cmp.PartialEqU8, liftFun2]
  · intro b hb
    rw [Slice.eq_iff] at hb
    simpa using hb

/-- The canonical text of a pair is a level, and its categories are the two of the pair. -/
theorem pair_text_level (lo hi : Nat) (lo_lt : lo < hi) (hi_lt : hi < 1024) :
    Level (PairText lo hi) (fun c => c = lo ∨ c = hi) := by
  have catlo : CatText (Text "c" ++ Decimal lo) lo :=
    ⟨Decimal lo, rfl, decimal_ne_nil lo, decimal_digits lo, decimal_value lo, by omega⟩
  have cathi : CatText (Text "c" ++ Decimal hi) hi :=
    ⟨Decimal hi, rfl, decimal_ne_nil hi, decimal_digits hi, decimal_value hi, hi_lt⟩
  have sens : Sens (Text "s0") :=
    Sens.first ⟨[48#u8], by rw [text_s]; decide, by simp, by
      intro d hd; simp at hd; rw [hd]; exact ⟨by decide, by decide⟩⟩
  have items := Items.more (Item.single catlo) (Items.last (Item.single cathi))
  have lvl := Level.categories sens items
  have eq : PairText lo hi = Text "s0" ++ Text ":" ++
      (Text "c" ++ Decimal lo ++ Text "," ++ (Text "c" ++ Decimal hi)) := by
    unfold PairText
    have : Text "s0:c" = Text "s0" ++ Text ":" ++ Text "c" := by decide
    have h2 : Text ",c" = Text "," ++ Text "c" := by decide
    rw [this, h2]; simp
  rw [eq]
  convert lvl using 1

/-- What `read_pair` answers: nothing but a pair whose canonical text is the level, and that pair
for the canonical text of a pair. -/
theorem read_pair_spec (level : Slice Std.U8) :
    read_pair level ⦃ r =>
      (∀ p, r = some p → level.val = PairText p.1.val p.2.val ∧ p.1.val < p.2.val ∧ p.2.val < 1024) ∧
      (∀ lo hi : Std.U16, level.val = PairText lo.val hi.val → lo.val < hi.val → hi.val < 1024 →
        r = some (lo, hi)) ⦄ := by
  unfold read_pair
  step with parse_spec level as ⟨ o, ho_complete, ho_sound ⟩
  cases o with
  | none =>
    refine (WP.spec_ok _).mpr ⟨by simp, ?_⟩
    intro lo hi hl lo_lt hi_lt
    obtain ⟨cats, hc, _⟩ := ho_complete _ (hl ▸ pair_text_level lo.val hi.val lo_lt hi_lt)
    simp at hc
  | some cats =>
    step with read_pair_loop0_spec cats 0#u16 (by simp) as ⟨ low, hl1, hl2, hl3, hl4 ⟩
    step as ⟨ high, is_high ⟩
    step with read_pair_loop1_spec cats high (by omega) as ⟨ high1, hh1, hh2, hh3, hh4 ⟩
    step with pair_label_spec low high1 as ⟨ o1, iff1, bytes1 ⟩
    have zero : (0#u16).val = 0 := rfl
    -- the members of the set, when the level is the canonical one of lo and hi
    have first_and_second : ∀ lo hi : Std.U16, level.val = PairText lo.val hi.val → lo.val < hi.val →
        hi.val < 1024 → low = lo ∧ high1 = hi := by
      intro lo hi hl lo_lt hi_lt
      obtain ⟨cats', hc, hmem⟩ := ho_complete _ (hl ▸ pair_text_level lo.val hi.val lo_lt hi_lt)
      have hc' : cats = cats' := (Option.some.inj hc)
      subst hc'
      have mem : ∀ c, Mem cats c ↔ (c = lo.val ∨ c = hi.val) := hmem
      have low_lt : low.val < 1024 := by
        by_contra no
        have : low.val = 1024 := by omega
        have := hl4 lo.val (by omega) (by omega)
        exact this ((mem _).mpr (Or.inl rfl))
      have low_mem := (mem _).mp (hl3 low_lt)
      have low_le : low.val ≤ lo.val := by
        by_contra no
        exact hl4 lo.val (by omega) (by omega) ((mem _).mpr (Or.inl rfl))
      have low_is : low.val = lo.val := by
        rcases low_mem with h | h
        · exact h
        · omega
      have high1_lt : high1.val < 1024 := by
        by_contra no
        have := hh4 hi.val (by omega) (by omega)
        exact this ((mem _).mpr (Or.inr rfl))
      have high1_mem := (mem _).mp (hh3 high1_lt)
      have high1_le : high1.val ≤ hi.val := by
        by_contra no
        exact hh4 hi.val (by omega) (by omega) ((mem _).mpr (Or.inr rfl))
      have high1_is : high1.val = hi.val := by
        rcases high1_mem with h | h
        · omega
        · exact h
      exact ⟨UScalar.eq_of_val_eq low_is, UScalar.eq_of_val_eq high1_is⟩
    cases o1 with
    | none =>
      refine (WP.spec_ok _).mpr ⟨by simp, ?_⟩
      intro lo hi hl lo_lt hi_lt
      obtain ⟨e1, e2⟩ := first_and_second lo hi hl lo_lt hi_lt
      subst e1; subst e2
      exact absurd (iff1.mp rfl) (by simp [lo_lt, hi_lt])
    | some label =>
      dsimp only
      step with bytes1 label rfl as ⟨ sb, hsb ⟩
      step with slice_eq_spec sb level as ⟨ b, hb ⟩
      have lt_pair : low.val < high1.val ∧ high1.val < 1024 := by
        by_contra no
        exact absurd (iff1.mpr no) (by simp)
      by_cases same : b = true
      · simp only [same, ite_true]
        have lvl_eq : level.val = PairText low.val high1.val := by
          rw [← hsb]; exact (hb.mp same).symm
        refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
        · intro p hp
          have hp' : p = (low, high1) := (Option.some.inj hp).symm
          subst hp'
          exact ⟨lvl_eq, lt_pair.1, lt_pair.2⟩
        · intro lo hi hl lo_lt hi_lt
          obtain ⟨e1, e2⟩ := first_and_second lo hi hl lo_lt hi_lt
          subst e1; subst e2; rfl
      · have same' : b = false := by simpa using same
        simp only [same', Bool.false_eq_true, ite_false]
        refine (WP.spec_ok _).mpr ⟨by simp, ?_⟩
        intro lo hi hl lo_lt hi_lt
        obtain ⟨e1, e2⟩ := first_and_second lo hi hl lo_lt hi_lt
        subst e1; subst e2
        exfalso
        apply same
        exact hb.mpr (by rw [hsb, hl])

end McsCore
