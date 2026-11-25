-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims about `pick` of Spec.lean.
-- Why it is needed: Theorems.lean lists them.
-- Read before this file: ThePick.lean.
-- Notation: `Offers`, `ReachesNone`, `CoversNone` are in Spec.lean.
import McsCore.ClaimsOfPairs
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- When each category of a level is a category of the pair (lo, hi) the level is reached by,
and covered by, the pair; so a pair that is reached by none, or covered by none, has a category
of its own to say against each level with categories. -/
theorem separate_of_cond (b : Slice Std.U8) (lo hi : Nat) (lo_lt : lo < hi) (hi_lt : hi < 1024)
    (bytes : b.val = PairText lo hi) (pass : Std.I32) (u : alloc.vec.Vec Std.U8)
    (isp : pass = 0#i32 ∨ pass = 1#i32) (cond : Cond pass b.val u) :
    ∀ T, Level u.val T → (∃ c, T c) → ∃ c, T c ∧ c ≠ lo ∧ c ≠ hi := by
  intro T lu ne
  by_contra no
  have sub : ∀ c, T c → (c = lo ∨ c = hi) := by
    intro c hc
    by_contra h
    exact no ⟨c, hc, fun e => h (Or.inl e), fun e => h (Or.inr e)⟩
  have lvl : Level b.val (fun c => c = lo ∨ c = hi) := by
    rw [bytes]; exact pair_text_level lo hi lo_lt hi_lt
  rcases isp with rfl | rfl
  · refine (cond.1 rfl) (Or.inr ⟨_, T, lvl, lu, ⟨lo, Or.inl rfl⟩, ne, Or.inr sub⟩)
  · refine (cond.2 rfl) ⟨_, T, lvl, lu, ne, sub⟩

/-- Proof of `TheFreshLevelIsSeparate`. -/
theorem the_fresh_level_is_separate : TheFreshLevelIsSeparate := by
  intro rand used
  refine WP.spec_mono (pick_outer_spec rand used) ?_
  rintro r ⟨first, -, -, -⟩ label hr
  have from_passes : ∀ (pass : Std.I32), (pass = 0#i32 ∨ pass = 1#i32) → ∀ k b,
      Passes pass rand used k label b → ∃ low high : Std.U16, low.val < high.val ∧ high.val < 1024 ∧
        Label.as_bytes label ⦃ b => b.val = PairText low.val high.val ∧
          read_pair b ⦃ p => p = some (low, high) ⦄ ∧
          ∀ u ∈ used.val, ∀ T, Level u.val T → (∃ c, T c) → ∃ c, T c ∧ c ≠ low.val ∧ c ≠ high.val ⦄ := by
    intro pass isp k b ⟨lt, ⟨k', hk', hatt⟩, hbl, hall⟩
    obtain ⟨o, ho, label0, rfl, lo, hi, lo_lt, hi_lt, hbytes⟩ :=
      (by
        obtain ⟨o, ho, h⟩ := spec_returns (attempt_spec rand k' (by omega))
        obtain ⟨label0, h1, h2⟩ := h
        exact ⟨o, ho, label0, h1, h2⟩ :
        ∃ o, attempt rand k' = ok o ∧ ∃ label0, o = some label0 ∧ ∃ lo hi : Std.U16, lo.val < hi.val ∧
          hi.val < 1024 ∧ Label.as_bytes label0 ⦃ b => b.val = PairText lo.val hi.val ⦄)
    rw [ho] at hatt
    have l_is : label0 = label := Option.some.inj (Result.ok_injective hatt)
    subst l_is
    obtain ⟨b', hb', hb'v⟩ := spec_returns hbytes
    rw [hb'] at hbl
    have b_is : b' = b := Result.ok_injective hbl
    subst b_is
    refine ⟨lo, hi, lo_lt, hi_lt, ?_⟩
    rw [hb']
    refine (WP.spec_ok _).mpr ⟨hb'v, ?_, ?_⟩
    · refine WP.spec_mono (read_pair_spec b') ?_
      rintro p ⟨-, again⟩
      exact again lo hi hb'v lo_lt hi_lt
    · intro u hu T lu ne
      exact separate_of_cond b' lo.val hi.val lo_lt hi_lt hb'v pass u isp (hall u hu) T lu ne
  rcases first label hr with ⟨k, b, hp⟩ | ⟨⟨k, b, hp⟩, -⟩
  · exact from_passes 0#i32 (Or.inl rfl) k b hp
  · exact from_passes 1#i32 (Or.inr rfl) k b hp

/-- An attempt that gives a label, with each used level fine for the pass, is what `Passes` says. -/
theorem passes_of_offers (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)) (k : Nat)
    (label : Label) (b : Slice Std.U8) (offers : Offers rand k label b)
    (pass : Std.I32) (all : ∀ u ∈ used.val, Cond pass b.val u) : Passes pass rand used k label b :=
  ⟨offers.1, offers.2.2.1, offers.2.2.2, all⟩

/-- Proof of `APairThatReachesNoLevelWins`. -/
theorem a_pair_that_reaches_no_level_wins : APairThatReachesNoLevelWins := by
  intro rand used ⟨k, label, b, offers, none_reached⟩
  refine WP.spec_mono (pick_outer_spec rand used) ?_
  rintro r ⟨first, some0, -, -⟩
  have sp0 : SomePasses 0#i32 rand used :=
    ⟨k, label, b, offers.2.1, passes_of_offers rand used k label b offers 0#i32
      (fun u hu => (cond_zero b.val u).mpr (none_reached u hu))⟩
  obtain ⟨l, hl⟩ := some0 sp0
  rcases first l hl with ⟨k', b', hp⟩ | ⟨-, no⟩
  · exact ⟨l, b', hl, hp.2.2.1, fun u hu => (cond_zero b'.val u).mp (hp.2.2.2 u hu)⟩
  · exact absurd sp0 no

/-- Proof of `NoneOnlyWhenNoAttemptPasses`. -/
theorem none_only_when_no_attempt_passes : NoneOnlyWhenNoAttemptPasses := by
  intro rand used
  refine WP.spec_mono (pick_outer_spec rand used) ?_
  rintro r ⟨-, -, -, none_case⟩ hr k label b offers covers
  have sp1 : SomePasses 1#i32 rand used :=
    ⟨k, label, b, offers.2.1, passes_of_offers rand used k label b offers 1#i32
      (fun u hu => (cond_one b.val u).mpr (covers u hu))⟩
  exact (none_case hr).2 sp1

/-- Proof of `WithNoLevelInUseALabelIsAnswered`. -/
theorem with_no_level_in_use_a_label_is_answered : WithNoLevelInUseALabelIsAnswered := by
  intro rand used empty two
  have sl : rand.length = rand.val.length := rfl
  have no_used : ∀ u ∈ used.val, False := by
    intro u hu
    have : used.val.length = 0 := empty
    rw [List.length_eq_zero_iff.mp this] at hu
    simp at hu
  obtain ⟨o, ho, label0, rfl, lo, hi, lo_lt, hi_lt, hbytes⟩ :=
    (by
      obtain ⟨o, ho, h⟩ := spec_returns (attempt_spec rand 0#usize (by simp; omega))
      obtain ⟨label0, h1, h2⟩ := h
      exact ⟨o, ho, label0, h1, h2⟩ :
      ∃ o, attempt rand 0#usize = ok o ∧ ∃ label0, o = some label0 ∧ ∃ lo hi : Std.U16, lo.val < hi.val ∧
        hi.val < 1024 ∧ Label.as_bytes label0 ⦃ b => b.val = PairText lo.val hi.val ⦄)
  obtain ⟨b, hb, _⟩ := spec_returns hbytes
  have wins := a_pair_that_reaches_no_level_wins rand used
    ⟨0, label0, b, ⟨by simp; omega, rfl, ⟨0#usize, rfl, ho⟩, hb⟩, fun u hu => (no_used u hu).elim⟩
  refine WP.spec_mono wins ?_
  rintro r ⟨label, b', hr, -⟩
  exact ⟨label, hr⟩

end McsCore
