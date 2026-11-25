-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `attempt` and `pick`: the fresh level taken from random numbers, with two
--    passes over the same attempts.
-- Why it is needed: this is the allocator of the levels of the containers.
-- Read before this file: TheReadPair.lean, TheOverlap.lean.
-- Notation: `Passes pass rand used k label b`: the attempt `k` gives `label` (bytes `b`) and each
--    level in use is fine for the pass.
import McsCore.TheReadPair
import McsCore.TheOverlap
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- A pair of categories that fits gives a label whose bytes are the canonical ones of that pair. -/
theorem pair_label_some (lo hi : Std.U16) (h1 : lo.val < hi.val) (h2 : hi.val < 1024) :
    pair_label lo hi ⦃ o => ∃ label, o = some label ∧ ∃ lo' hi' : Std.U16, lo'.val < hi'.val ∧
      hi'.val < 1024 ∧ Label.as_bytes label ⦃ b => b.val = PairText lo'.val hi'.val ⦄ ⦄ := by
  refine WP.spec_mono (pair_label_spec lo hi) ?_
  rintro o ⟨iff1, bytes1⟩
  cases o with
  | none => exact absurd (iff1.mp rfl) (by simp [h1, h2])
  | some label => exact ⟨label, rfl, lo, hi, h1, h2, bytes1 label rfl⟩

/-- What an attempt does: for two random numbers it gives the label of a pair of two different
categories in order, below 1024. -/
theorem attempt_spec (rand : Slice Std.U32) (a : Std.Usize) (inside : a.val + 1 < rand.length) :
    attempt rand a ⦃ o => ∃ label, o = some label ∧ ∃ lo hi : Std.U16, lo.val < hi.val ∧ hi.val < 1024 ∧
      Label.as_bytes label ⦃ b => b.val = PairText lo.val hi.val ⦄ ⦄ := by
  unfold attempt
  have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  step as ⟨ i, is_i ⟩
  step as ⟨ i1, is_i1 ⟩
  step as ⟨ i2, is_i2 ⟩
  step as ⟨ first, is_first ⟩
  step as ⟨ i3, is_i3 ⟩
  step as ⟨ i4, is_i4 ⟩
  step as ⟨ i5, is_i5 ⟩
  step as ⟨ i6, is_i6 ⟩
  step as ⟨ i7, is_i7 ⟩
  step as ⟨ second, is_second ⟩
  have first_v : first.val = i.val % 1024 := by
    rw [is_first, UScalar.cast_val_eq]; simp [is_i2, is_i1, cat]; omega
  have second_v : second.val = i4.val % 1023 := by
    rw [is_second, UScalar.cast_val_eq]
    have : i5.val = 1024 := by rw [is_i5, UScalar.cast_val_eq]; simp [cat]
    simp [is_i7, is_i6, this]; omega
  have first_lt : first.val < 1024 := by omega
  have second_lt : second.val < 1023 := by omega
  by_cases ge : second ≥ first
  · have ge' : first.val ≤ second.val := by scalar_tac
    simp only [ge, ite_true]
    step as ⟨ second1, is_s1 ⟩
    have lt : first < second1 := by scalar_tac
    simp only [lt, ite_true]
    exact pair_label_some first second1 (by omega) (by omega)
  · have lt' : second.val < first.val := by scalar_tac
    simp only [ge, ite_false, bind_tc_ok, bind_ok]
    have not_lt : ¬ first < second := by scalar_tac
    simp only [not_lt, ite_false]
    exact pair_label_some second first lt' first_lt

/-- What a used level must be for the label of a pass: not reached by it (first pass), not covered by
it (second pass). -/
def Cond (pass : Std.I32) (label : List Std.U8) (v : alloc.vec.Vec Std.U8) : Prop :=
  (pass = 0#i32 → ¬ Reach label v.val) ∧ (pass = 1#i32 → ¬ Covers label v.val)

/-- The bytes of a `Vec` seen as a slice are those of the `Vec`. -/
theorem deref_val (v : alloc.vec.Vec Std.U8) : (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]

/-- One step of the loop over the levels in use in the first pass: the flag stays true unless the
level is reached by the label. -/
theorem inner_overlap (used : Slice (alloc.vec.Vec Std.U8)) (b0 : Slice Std.U8) (u : Std.Usize)
    (free : Bool) (below : u.val < used.length) :
    ∃ free2 : Bool, (do
      let v ← used.index_usize u
      let b ← overlap b0 v.deref
      if b = true then ok false else ok free : Result Bool) = ok free2 ∧
      (free2 = true ↔ free = true ∧ ¬ Reach b0.val used.val[u.val]!.val) := by
  have is_v : used.index_usize u = ok used.val[u.val] := by
    have := Slice.index_usize_spec used u below
    obtain ⟨x, hx, hx'⟩ := spec_returns this
    rw [hx, hx']
  rw [is_v, bind_ok]
  obtain ⟨r1, hr1, h1⟩ := spec_returns (overlap_spec b0 (used.val[u.val]).deref)
  have vget : used.val[u.val]! = used.val[u.val] := by
    simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem below]
  rw [hr1, bind_ok]
  by_cases rt : r1 = true
  · refine ⟨false, by simp [rt], ?_⟩
    have := h1.mp rt
    simp only [Bool.false_eq_true, false_iff, not_and]
    intro _ hn; exact hn (by rw [vget]; simpa [Reach, deref_val] using this)
  · refine ⟨free, by simp [rt], ?_⟩
    have := mt h1.mpr rt
    constructor
    · intro h; exact ⟨h, by rw [vget]; simpa [Reach, deref_val] using this⟩
    · exact fun h => h.1

/-- One step of the loop over the levels in use in the second pass: the flag stays true unless the
label covers the level. -/
theorem inner_covers (used : Slice (alloc.vec.Vec Std.U8)) (b0 : Slice Std.U8) (u : Std.Usize)
    (free : Bool) (below : u.val < used.length) :
    ∃ free2 : Bool, (do
      let v ← used.index_usize u
      let b ← contains b0 v.deref
      if b = true then ok false else ok free : Result Bool) = ok free2 ∧
      (free2 = true ↔ free = true ∧ ¬ Covers b0.val used.val[u.val]!.val) := by
  have is_v : used.index_usize u = ok used.val[u.val] := by
    have := Slice.index_usize_spec used u below
    obtain ⟨x, hx, hx'⟩ := spec_returns this
    rw [hx, hx']
  rw [is_v, bind_ok]
  obtain ⟨r1, hr1, h1⟩ := spec_returns (contains_spec b0 (used.val[u.val]).deref)
  have vget : used.val[u.val]! = used.val[u.val] := by
    simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem below]
  rw [hr1, bind_ok]
  by_cases rt : r1 = true
  · refine ⟨false, by simp [rt], ?_⟩
    have := h1.mp rt
    simp only [Bool.false_eq_true, false_iff, not_and]
    intro _ hn; exact hn (by rw [vget]; simpa [Covers, deref_val] using this)
  · refine ⟨free, by simp [rt], ?_⟩
    have := mt h1.mpr rt
    constructor
    · intro h; exact ⟨h, by rw [vget]; simpa [Covers, deref_val] using this⟩
    · exact fun h => h.1

/-- For the first pass, a level in use is fine when the label does not reach it. -/
theorem cond_zero (l : List Std.U8) (v : alloc.vec.Vec Std.U8) :
    Cond 0#i32 l v ↔ ¬ Reach l v.val := by
  unfold Cond
  have : ¬ (0#i32 = 1#i32) := by decide
  simp [this]

/-- For the second pass, a level in use is fine when the label does not cover it. -/
theorem cond_one (l : List Std.U8) (v : alloc.vec.Vec Std.U8) :
    Cond 1#i32 l v ↔ ¬ Covers l v.val := by
  unfold Cond
  have : ¬ (1#i32 = 0#i32) := by decide
  simp [this]

/-- For no pass at all, every level in use is fine. -/
theorem cond_other (pass : Std.I32) (l : List Std.U8) (v : alloc.vec.Vec Std.U8)
    (p0 : ¬ pass = 0#i32) (p1 : ¬ pass = 1#i32) : Cond pass l v := by
  unfold Cond; exact ⟨fun h => absurd h p0, fun h => absurd h p1⟩

/-- The loop of `pick` over the levels in use: it says true exactly when the flag was true and each
level in use is fine for the pass. -/
theorem pick_inner_spec (used : Slice (alloc.vec.Vec Std.U8)) (pass : Std.I32) (label : Label)
    (b0 : Slice Std.U8) (hb : Label.as_bytes label = ok b0) (free : Bool) (u : Std.Usize)
    (inside : u.val ≤ used.length) :
    pick_loop0_loop0_loop0 used pass label free u ⦃ r =>
      r = true ↔ free = true ∧ ∀ k, u.val ≤ k → k < used.length → Cond pass b0.val used.val[k]! ⦄ := by
  unfold pick_loop0_loop0_loop0
  apply loop_answers (fun x : Bool × Std.Usize => pick_loop0_loop0_loop0.body used pass label x.1 x.2)
    (fun x y => y = true ↔ x.1 = true ∧ ∀ k, x.2.val ≤ k → k < used.length →
      Cond pass b0.val used.val[k]!)
    (fun x => used.length - x.2.val) (fun x => x.2.val ≤ used.length)
  · rintro ⟨free', u'⟩ inside'
    simp only at inside' ⊢
    unfold pick_loop0_loop0_loop0.body
    have is_len : (Slice.len used).val = used.length := by simp [Slice.len]
    by_cases below : u' < Slice.len used
    · simp only [below, ite_true]
      have below' : u'.val < used.length := by scalar_tac
      have room : u'.val + 1 ≤ Usize.max := by scalar_tac
      have vget : used.val[u'.val]! = used.val[u'.val] := by
        simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem below']
      have cond_iff : ∀ (free : Bool) (free2 : Bool),
          (free2 = true ↔ free = true ∧ Cond pass b0.val used.val[u'.val]!) →
          ((free2 = true ∧ ∀ k, u'.val + 1 ≤ k → k < used.length → Cond pass b0.val used.val[k]!) ↔
            (free = true ∧ ∀ k, u'.val ≤ k → k < used.length → Cond pass b0.val used.val[k]!)) := by
        intro free free2 h
        rw [h]
        constructor
        · rintro ⟨⟨hf, hc⟩, rest⟩
          refine ⟨hf, fun k a b => ?_⟩
          rcases Nat.eq_or_lt_of_le a with eq | lt
          · rw [← eq]; exact hc
          · exact rest k lt b
        · rintro ⟨hf, all⟩
          exact ⟨⟨hf, all _ (le_refl _) below'⟩, fun k a b => all k (by omega) b⟩
      have is_u1 : ∀ u1 : Std.Usize, u1.val = u'.val + 1 → u1.val ≤ used.length := by intro u1 h; omega
      by_cases p0 : pass = 0#i32
      · have n01 : ¬ (0#i32 = 1#i32) := by decide
        simp only [p0, ite_true, n01, ite_false, hb, bind_tc_ok, bind_ok]
        obtain ⟨free2, hf2, hiff⟩ := inner_overlap used b0 u' free' below'
        rw [hf2, bind_ok]
        step as ⟨ u1, is_u1' ⟩
        refine ⟨by omega, by omega, ?_⟩
        intro y hy
        rw [hy]
        subst p0
        have ci : (free2 = true ↔ free' = true ∧ Cond 0#i32 b0.val used.val[u'.val]!) := by
          rw [cond_zero]; exact hiff
        rw [← cond_iff free' free2 ci]
        rw [is_u1']
      · by_cases p1 : pass = 1#i32
        · have n10 : ¬ (1#i32 = 0#i32) := by decide
          simp only [p1, ite_true, n10, ite_false, hb, bind_tc_ok, bind_ok]
          obtain ⟨free2, hf2, hiff⟩ := inner_covers used b0 u' free' below'
          rw [hf2, bind_ok]
          step as ⟨ u1, is_u1' ⟩
          refine ⟨by omega, by omega, ?_⟩
          intro y hy
          rw [hy]
          subst p1
          have ci : (free2 = true ↔ free' = true ∧ Cond 1#i32 b0.val used.val[u'.val]!) := by
            rw [cond_one]; exact hiff
          rw [← cond_iff free' free2 ci]
          rw [is_u1']
        · simp only [p0, p1, ite_false, bind_tc_ok, bind_ok]
          step as ⟨ u1, is_u1' ⟩
          refine ⟨by omega, by omega, ?_⟩
          intro y hy
          rw [hy, is_u1']
          have ci : (free' = true ↔ free' = true ∧ Cond pass b0.val used.val[u'.val]!) :=
            ⟨fun h => ⟨h, cond_other _ _ _ p0 p1⟩, fun h => h.1⟩
          rw [← cond_iff free' free' ci]
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : u'.val = used.length := by scalar_tac
      constructor
      · intro h; exact ⟨h, fun k a b => by omega⟩
      · exact fun h => h.1
  · exact inside

/-- The attempt `k` gives the label `label`, whose bytes are `b`, and each level in use is as the
pass `pass` wants. -/
def Passes (pass : Std.I32) (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8))
    (k : Nat) (label : Label) (b : Slice Std.U8) : Prop :=
  k + 1 < rand.length ∧ (∃ k' : Std.Usize, k'.val = k ∧ attempt rand k' = ok (some label)) ∧
    Label.as_bytes label = ok b ∧ ∀ u ∈ used.val, Cond pass b.val u

/-- Each element of a list satisfies a claim exactly when each place does. -/
theorem mem_iff_getElem (used : Slice (alloc.vec.Vec Std.U8)) (P : alloc.vec.Vec Std.U8 → Prop) :
    (∀ u ∈ used.val, P u) ↔ ∀ k, 0 ≤ k → k < used.length → P used.val[k]! := by
  constructor
  · intro h k _ lt
    apply h
    rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt]
    exact List.getElem_mem lt
  · intro h u hu
    obtain ⟨k, lt, rfl⟩ := List.getElem_of_mem hu
    have := h k (Nat.zero_le _) lt
    rwa [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt] at this

/-- The loop of `pick` over the attempts of a pass: it is done exactly when some attempt passes, and
then its label is the answer. -/
theorem pick_middle_spec (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8))
    (found : Option Label) (done1 : Bool) (pass : Std.I32) (a : Std.Usize)
    (even : a.val % 2 = 0) (inside : a.val ≤ rand.length) :
    pick_loop0_loop0 rand used found done1 pass a ⦃ r =>
      (done1 = true → r = (found, true)) ∧
      (done1 = false → (r.2 = true ↔ ∃ k label b, a.val ≤ k ∧ k % 2 = 0 ∧
          Passes pass rand used k label b) ∧
        (r.2 = true → ∃ k label b, a.val ≤ k ∧ k % 2 = 0 ∧ Passes pass rand used k label b ∧
          r.1 = some label) ∧
        (r.2 = false → r.1 = found)) ⦄ := by
  unfold pick_loop0_loop0
  apply loop_answers
    (fun x : Option Label × Bool × Std.Usize => pick_loop0_loop0.body rand used pass x.1 x.2.1 x.2.2)
    (fun x y =>
      (x.2.1 = true → y = (x.1, true)) ∧
      (x.2.1 = false → (y.2 = true ↔ ∃ k label b, x.2.2.val ≤ k ∧ k % 2 = 0 ∧
          Passes pass rand used k label b) ∧
        (y.2 = true → ∃ k label b, x.2.2.val ≤ k ∧ k % 2 = 0 ∧
          Passes pass rand used k label b ∧ y.1 = some label) ∧
        (y.2 = false → y.1 = x.1)))
    (fun x => rand.length - x.2.2.val) (fun x => x.2.2.val ≤ rand.length ∧ x.2.2.val % 2 = 0)
  · rintro ⟨found', done', a'⟩ ⟨inside', even'⟩
    simp only at inside' even' ⊢
    unfold pick_loop0_loop0.body
    have is_len : (Slice.len rand).val = rand.length := by simp [Slice.len]
    by_cases dn : done' = true
    · simp only [dn, ite_true]
      refine (WP.spec_ok _).mpr ⟨fun _ => rfl, fun h => absurd h (by simp [dn])⟩
    · have dn' : done' = false := by simpa using dn
      simp only [dn, Bool.false_eq_true, ite_false]
      have hmax : Usize.max % 2 = 1 := by
        rcases Usize.bounds_eq with h | h <;> rw [h]
        · rw [U32.max_eq]
        · rw [U64.max_eq]
      have room1 : a'.val + 1 ≤ Usize.max := by
        have : a'.val ≤ Usize.max := by scalar_tac
        omega
      obtain ⟨i0, hi0, is_i0⟩ : ∃ i0 : Std.Usize, (a' + 1#usize : Result Std.Usize) = ok i0 ∧
          i0.val = a'.val + 1 := by
        obtain ⟨x, hx, hx'⟩ := spec_returns (Std.Usize.add_spec (x := a') (y := 1#usize) (by simpa using room1))
        exact ⟨x, hx, by simpa using hx'⟩
      rw [hi0, bind_ok]
      by_cases lt' : a'.val + 1 < rand.length
      · have lt : i0 < Slice.len rand := by scalar_tac
        simp only [lt, ite_true]
        obtain ⟨o, ho, hex⟩ := spec_returns (attempt_spec rand a' lt')
        obtain ⟨label0, rfl, lo, hi, hlt, hhi, hbytes⟩ := hex
        obtain ⟨b0, hb0, _⟩ := spec_returns hbytes
        rw [ho, bind_ok]
        step with pick_inner_spec used pass label0 b0 hb0 true 0#usize (by simp) as ⟨ free, hfree ⟩
        have free_iff : free = true ↔ ∀ u ∈ used.val, Cond pass b0.val u := by
          rw [hfree, mem_iff_getElem]
        have passes_a : ∀ label b, Passes pass rand used a'.val label b ↔
            (label = label0 ∧ b = b0 ∧ ∀ u ∈ used.val, Cond pass b0.val u) := by
          intro label b
          constructor
          · rintro ⟨_, ⟨k', hk', hk⟩, hbb, hall⟩
            have k_is : k' = a' := UScalar.eq_of_val_eq (by rw [hk'])
            subst k_is
            rw [ho] at hk
            have l_is : label0 = label := (Option.some.inj (Result.ok_injective hk))
            subst l_is
            rw [hb0] at hbb
            have b_is : b0 = b := Result.ok_injective hbb
            subst b_is
            exact ⟨rfl, rfl, hall⟩
          · rintro ⟨rfl, rfl, hall⟩
            exact ⟨lt', ⟨a', rfl, ho⟩, hb0, hall⟩
        by_cases hfree' : free = true
        · simp only [hfree', ite_true, bind_tc_ok, bind_ok]
          step as ⟨ a1, is_a1 ⟩
          refine ⟨by omega, by omega, by omega, ?_⟩
          intro y h1 h2
          have y_is : y = (some label0, true) := h1 (by simp)
          subst y_is
          refine ⟨fun h => h.elim, ?_, ?_, ?_⟩
          · exact ⟨fun _ => ⟨a'.val, label0, b0, le_refl _, even', (passes_a _ _).mpr ⟨rfl, rfl, free_iff.mp hfree'⟩⟩,
              fun _ => rfl⟩
          · exact fun _ => ⟨a'.val, label0, b0, le_refl _, even', (passes_a _ _).mpr ⟨rfl, rfl, free_iff.mp hfree'⟩, rfl⟩
          · intro h; exact absurd h (by simp)
        · simp only [hfree', Bool.false_eq_true, ite_false, bind_tc_ok, bind_ok]
          step as ⟨ a1, is_a1 ⟩
          refine ⟨by omega, by omega, by omega, ?_⟩
          intro y h1 h2
          have h2' := h2 (by simp)
          have not_here : ∀ label b, ¬ Passes pass rand used a'.val label b := by
            intro label b hp
            obtain ⟨-, -, hall⟩ := (passes_a label b).mp hp
            exact hfree' (free_iff.mpr hall)
          refine ⟨fun h => h.elim, ?_, ?_, ?_⟩
          · rw [h2'.1]
            constructor
            · rintro ⟨k, label, b, hk, hk2, hp⟩
              exact ⟨k, label, b, by omega, hk2, hp⟩
            · rintro ⟨k, label, b, hk, hk2, hp⟩
              refine ⟨k, label, b, ?_, hk2, hp⟩
              have : k ≠ a'.val := fun e => not_here label b (e ▸ hp)
              omega
          · intro hy
            obtain ⟨k, label, b, hk, hk2, hp, hl⟩ := h2'.2.1 hy
            exact ⟨k, label, b, by omega, hk2, hp, hl⟩
          · intro hy
            exact h2'.2.2 hy
      · have lt : ¬ i0 < Slice.len rand := by scalar_tac
        simp only [lt, ite_false]
        refine (WP.spec_ok _).mpr ⟨fun h => h.elim, fun _ => ⟨?_, ?_, ?_⟩⟩
        · constructor
          · intro h; exact absurd h (by simp)
          · rintro ⟨k, label, b, hk, hk2, hp⟩
            have := hp.1; omega
        · intro h; exact absurd h (by simp)
        · intro _; rfl
  · exact ⟨inside, even⟩

/-- Some attempt gives a label that the pass `pass` accepts. -/
def SomePasses (pass : Std.I32) (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)) : Prop :=
  ∃ k label b, k % 2 = 0 ∧ Passes pass rand used k label b

/-- What `pick` answers, as the claims say it, from the first pass. -/
def AnswerZero (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)) (y : Option Label) : Prop :=
  (∀ l, y = some l → (∃ k b, Passes 0#i32 rand used k l b) ∨
    ((∃ k b, Passes 1#i32 rand used k l b) ∧ ¬ SomePasses 0#i32 rand used)) ∧
  (SomePasses 0#i32 rand used → ∃ l, y = some l) ∧
  ((¬ SomePasses 0#i32 rand used ∧ SomePasses 1#i32 rand used) → ∃ l, y = some l) ∧
  (y = none → ¬ SomePasses 0#i32 rand used ∧ ¬ SomePasses 1#i32 rand used)

/-- What `pick` answers, as the claims say it, from the second pass. -/
def AnswerOne (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)) (y : Option Label) : Prop :=
  (∀ l, y = some l → ∃ k b, Passes 1#i32 rand used k l b) ∧
  (SomePasses 1#i32 rand used → ∃ l, y = some l) ∧ (y = none → ¬ SomePasses 1#i32 rand used)

/-- What `pick` answers: a label of the first pass if some attempt passes it, else one of the second
pass, else nothing. -/
theorem pick_outer_spec (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)) :
    pick_loop0 rand used none false 0#i32 ⦃ r => AnswerZero rand used r ⦄ := by
  unfold pick_loop0
  have main := loop_answers
    (fun x : Option Label × Bool × Std.I32 => pick_loop0.body rand used x.1 x.2.1 x.2.2)
    (fun x y =>
      (x.2.1 = true → y = x.1) ∧
      (x.2.1 = false → x.1 = none → x.2.2 = 0#i32 → AnswerZero rand used y) ∧
      (x.2.1 = false → x.1 = none → x.2.2 = 1#i32 → AnswerOne rand used y) ∧
      (x.2.1 = false → x.1 = none → x.2.2 = 2#i32 → y = none))
    (fun x => if x.2.1 = true then 0 else (3 - x.2.2.val).toNat)
    (fun x => x.2.1 = false → x.1 = none ∧ (x.2.2 = 0#i32 ∨ x.2.2 = 1#i32 ∨ x.2.2 = 2#i32))
    (none, false, 0#i32) ?_ (fun _ => ⟨rfl, Or.inl rfl⟩)
  · refine WP.spec_mono main ?_
    intro y ⟨_, h0, _⟩
    exact h0 rfl rfl rfl
  · rintro ⟨found', done', pass'⟩ inv
    simp only at inv ⊢
    unfold pick_loop0.body
    have z : (0#usize).val = 0 := rfl
    by_cases dn : done' = true
    · simp only [dn, ite_true]
      refine (WP.spec_ok _).mpr ⟨fun _ => rfl, ?_, ?_, ?_⟩ <;>
      · intro h; exact absurd h (by simp [dn])
    · have dn' : done' = false := by simpa using dn
      obtain ⟨hfound, hpass⟩ := inv dn'
      subst hfound
      simp only [dn, Bool.false_eq_true, ite_false]
      rcases hpass with rfl | rfl | rfl
      · have lt : (0#i32 < 2#i32) := by decide
        simp only [lt, ite_true]
        step with pick_middle_spec rand used none false 0#i32 0#usize (by simp) (by simp)
          as ⟨ found1, done2, hm1, hm2, hm3, hm4 ⟩
        step as ⟨ pass1, is_pass1 ⟩
        have p1 : pass1 = 1#i32 := by
          apply IScalar.eq_of_val_eq
          simpa using is_pass1
        subst p1
        have sp0 : SomePasses 0#i32 rand used ↔ done2 = true := by
          unfold SomePasses; rw [hm2]; simp
        refine ⟨?_, ?_, ?_⟩
        · intro d; exact ⟨hm4 d, by simp⟩
        · by_cases d2 : done2 = true
          · simp only [d2, ite_true]
            decide
          · simp only [d2, Bool.false_eq_true, ite_false]
            decide
        · intro y a1 a2 a3 a4
          have n01 : ¬ (0#i32 = 1#i32) := by decide
          have n02 : ¬ (0#i32 = 2#i32) := by decide
          refine ⟨fun h => h.elim, ?_, fun h => absurd h n01, fun h => absurd h n02⟩
          by_cases d2 : done2 = true
          · obtain ⟨k, label, b, _, hk2, hp, hl⟩ := hm3 d2
            have y_is : y = some label := by rw [a1 d2, hl]
            refine ⟨?_, fun _ => ⟨label, y_is⟩, fun h => absurd (sp0.mpr d2) h.1, fun h => by simp [y_is] at h⟩
            intro l hl'
            rw [y_is] at hl'
            have : label = l := Option.some.inj hl'
            subst this
            exact Or.inl ⟨k, b, hp⟩
          · have d2' : done2 = false := by simpa using d2
            have a3' := a3 d2' (hm4 d2') rfl
            have no0 : ¬ SomePasses 0#i32 rand used := fun h => d2 (sp0.mp h)
            obtain ⟨b1, b2, b3⟩ := a3'
            refine ⟨?_, fun h => absurd h no0, fun ⟨_, h⟩ => b2 h, fun h => ⟨no0, b3 h⟩⟩
            intro l hl'
            obtain ⟨k, b, hp⟩ := b1 l hl'
            exact Or.inr ⟨⟨k, b, hp⟩, no0⟩
      · have lt : (1#i32 < 2#i32) := by decide
        simp only [lt, ite_true]
        step with pick_middle_spec rand used none false 1#i32 0#usize (by simp) (by simp)
          as ⟨ found1, done2, hm1, hm2, hm3, hm4 ⟩
        step as ⟨ pass1, is_pass1 ⟩
        have p2 : pass1 = 2#i32 := by
          apply IScalar.eq_of_val_eq
          simpa using is_pass1
        subst p2
        have sp1 : SomePasses 1#i32 rand used ↔ done2 = true := by
          unfold SomePasses; rw [hm2]; simp
        refine ⟨?_, ?_, ?_⟩
        · intro d; exact ⟨hm4 d, by simp⟩
        · by_cases d2 : done2 = true
          · simp only [d2, ite_true]
            decide
          · simp only [d2, Bool.false_eq_true, ite_false]
            decide
        · intro y a1 a2 a3 a4
          have n10 : ¬ (1#i32 = 0#i32) := by decide
          have n12 : ¬ (1#i32 = 2#i32) := by decide
          refine ⟨fun h => h.elim, fun h => absurd h n10, ?_, fun h => absurd h n12⟩
          by_cases d2 : done2 = true
          · obtain ⟨k, label, b, _, hk2, hp, hl⟩ := hm3 d2
            have y_is : y = some label := by rw [a1 d2, hl]
            refine ⟨?_, fun _ => ⟨label, y_is⟩, fun h => by simp [y_is] at h⟩
            intro l hl'
            rw [y_is] at hl'
            have : label = l := Option.some.inj hl'
            subst this
            exact ⟨k, b, hp⟩
          · have d2' : done2 = false := by simpa using d2
            have y_none : y = none := a4 d2' (hm4 d2') rfl
            refine ⟨fun l hl' => by simp [y_none] at hl', fun h => absurd (sp1.mp h) d2, fun _ => ?_⟩
            exact fun h => d2 (sp1.mp h)
      · have lt : ¬ (2#i32 < 2#i32) := by decide
        simp only [lt, ite_false]
        refine (WP.spec_ok _).mpr ?_
        simp

end McsCore
