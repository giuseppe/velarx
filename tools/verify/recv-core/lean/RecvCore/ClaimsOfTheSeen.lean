-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about what the node keeps of a peer's filter
--   (`Seen`): what a whole filter and a delta do to it, what the filter says, when it is behind, and that a
--   whole filter then the deltas in order keep it current.
-- Why it is needed: Theorems.lean names what is proved; the proofs are here.
-- Read before this file: Spec.lean, ClaimsOfTheFilter.lean.
-- Notation: `UScalar.eq_equiv` turns an equality of two numbers of a type into one of their values;
--   `max a b` is the larger of two whole numbers (`omega` knows it); `subst` replaces a name by what it
--   is equal to.
import RecvCore.ClaimsOfTheFilter
open Aeneas Aeneas.Std Result velarx_recv_core
namespace RecvCore

/-- Proof of `WhatAWholeFilterDoes`: `full` compares the run and the version, then sets the run, the
version and the last heard. -/
theorem full_is (s : Seen) (e v : Std.U64) (held : Bool) : Seen.full s e v held ⦃ a =>
    (a.1 = OnFull.Stale ↔ e = s.epoch ∧ v.val < s.version.val ∧ held = true) ∧
    (a.1 = OnFull.Stale → a.2 = s) ∧
    (a.1 = OnFull.Take → a.2.epoch = e ∧ a.2.version = v ∧
      a.2.heard.val = max v.val (if e = s.epoch then s.heard.val else 0)) ⦄ := by
  unfold Seen.full
  split_ifs <;> step*
  all_goals simp_all [UScalar.eq_equiv, UScalar.lt_equiv, bne_iff_ne]
  all_goals omega

/-- Proof of `WhatADeltaDoes`: `delta` compares the run, then the version, and sets the run, the version
and the last heard. -/
theorem delta_is (s : Seen) (e upto : Std.U64) (held : Bool) : Seen.delta s e upto held ⦃ a =>
    (a.1 = OnDelta.Stale ↔ e = s.epoch ∧ upto.val ≤ s.version.val) ∧
    (a.1 = OnDelta.Stale → a.2 = s) ∧
    (a.1 = OnDelta.Add ↔ ¬ (e = s.epoch ∧ upto.val ≤ s.version.val) ∧ held = true) ∧
    (a.1 = OnDelta.Skip ↔ ¬ (e = s.epoch ∧ upto.val ≤ s.version.val) ∧ held = false) ∧
    (a.1 ≠ OnDelta.Stale → a.2.epoch = e ∧
      a.2.version.val = (if e = s.epoch then s.version.val else 0) ∧
      a.2.heard.val = (if e = s.epoch then max upto.val s.heard.val else max upto.val 1)) ⦄ := by
  unfold Seen.delta
  split_ifs <;> step*
  all_goals simp_all [UScalar.eq_equiv, UScalar.lt_equiv, UScalar.le_equiv]
  all_goals omega

/-- Proof of `WhatAWholeFilterDoes`: `full_is`. -/
theorem what_a_whole_filter_does : WhatAWholeFilterDoes :=
  full_is

/-- Proof of `WhatADeltaDoes`: `delta_is`. -/
theorem what_a_delta_does : WhatADeltaDoes :=
  delta_is

/-- `added` sets the version to `to` when `from` is the version held and is not 0. -/
theorem added_is (s : Seen) (base upto : Std.U64) : Seen.added s base upto ⦃ s' =>
    s'.epoch = s.epoch ∧ s'.heard = s.heard ∧
    (base = s.version ∧ base.val ≠ 0 → s'.version = upto) ∧
    (¬ (base = s.version ∧ base.val ≠ 0) → s'.version = s.version) ⦄ := by
  unfold Seen.added
  split_ifs with same nonzero
  · have nz : base.val ≠ 0 := by simpa [UScalar.eq_equiv] using nonzero
    exact (WP.spec_ok _).mpr ⟨rfl, rfl, fun _ => rfl, fun off => absurd ⟨same, nz⟩ off⟩
  · have zero : base.val = 0 := by simpa [UScalar.eq_equiv] using nonzero
    exact (WP.spec_ok _).mpr ⟨rfl, rfl, fun ⟨_, nz⟩ => absurd zero nz, fun _ => rfl⟩
  · exact (WP.spec_ok _).mpr ⟨rfl, rfl, fun ⟨on, _⟩ => absurd on same, fun _ => rfl⟩

/-- Proof of `WhatAddedDoes`: `added_is`. -/
theorem what_added_does : WhatAddedDoes :=
  added_is

/-- Proof of the second claim of `WhatSaysAnswersExactly`: `behind` compares `heard` with `version`. -/
theorem behind_is (s : Seen) : Seen.behind s ⦃ b => (b = true ↔ Behind s) ⦄ := by
  unfold Seen.behind Behind
  refine (WP.spec_ok _).mpr ?_
  simp [UScalar.lt_equiv]

/-- Proof of the first claim of `WhatSaysAnswersExactly`: `says` asks whether the filter is believed, whether it
contains the key, and whether it is behind. -/
theorem says_is (s : Seen) (believed contains : Bool) : Seen.says s believed contains ⦃ a =>
    (a = Said.No ↔ believed = true ∧ contains = false ∧ ¬ Behind s) ∧
    (a = Said.Maybe ↔ believed = true ∧ contains = true) ∧
    (a = Said.Unknown ↔ believed = false ∨ (contains = false ∧ Behind s)) ⦄ := by
  unfold Seen.says
  split_ifs with is_believed has_key
  · simp_all
  · refine WP.spec_bind (behind_is s) ?_
    intro late late_is
    split_ifs with is_late
    · simp_all
    · simp_all
  · simp_all

/-- Proof of `WhatSaysAnswersExactly`: `says_is` and `behind_is`. -/
theorem what_says_answers_exactly : WhatSaysAnswersExactly :=
  ⟨says_is, behind_is⟩

/-- Proof of `ADeltaThatDoesNotFollowLeavesTheFilterBehind`: `delta_is` says what the run, the version and
the last heard are after the delta (another run: version 0 and something heard), and `added_is` that the
version moves only when the delta goes from the version held and it is not 0. -/
theorem a_delta_that_does_not_follow_leaves_the_filter_behind :
    ADeltaThatDoesNotFollowLeavesTheFilterBehind := by
  intro s e base upto held
  refine WP.spec_mono (delta_is s e upto held) ?_
  rintro ⟨d, s1⟩ ⟨stale_is, _, _, _, moved⟩ not_stale
  obtain ⟨_, version_is, heard_is⟩ := moved not_stale
  refine WP.spec_mono (added_is s1 base upto) ?_
  rintro s2 ⟨_, same_heard, _, not_applies⟩
  have fresh : ¬ (e = s.epoch ∧ upto.val ≤ s.version.val) := fun h => not_stale (stale_is.mpr h)
  unfold Behind
  dsimp only at *
  refine ⟨fun same_run off => ?_, fun other_run => ?_⟩
  · -- the same run: the delta does not go from the version held, or from 0, so the version stays
    simp only [same_run, ite_true] at version_is heard_is
    have stays : ¬ (base = s1.version ∧ base.val ≠ 0) := by
      rintro ⟨on_version, nonzero⟩
      rcases off with elsewhere | zero
      · exact elsewhere (UScalar.eq_equiv _ _ |>.mpr (by rw [on_version]; exact version_is))
      · exact nonzero zero
    rw [not_applies stays, same_heard]
    simp [same_run] at fresh
    omega
  · -- another run: nothing of it is held (version 0) and something was heard of it
    simp only [other_run, ite_false] at version_is heard_is
    have stays : ¬ (base = s1.version ∧ base.val ≠ 0) := by
      rintro ⟨on_version, nonzero⟩
      exact nonzero (by rw [on_version]; exact version_is)
    rw [not_applies stays, same_heard]
    omega

/-- A delta of a version past the one held (not 0), to a filter that is current at that version, is
added, and leaves the filter current at the delta's version. -/
theorem a_following_delta_is_added (s : Seen) (e v t : Std.U64) (current : Current s e v)
    (nonzero : v.val ≠ 0) (later : v.val < t.val) :
    Seen.delta s e t true ⦃ a => a.1 = OnDelta.Add ∧
      Seen.added a.2 v t ⦃ s' => Current s' e t ∧ ¬ Behind s' ⦄ ⦄ := by
  obtain ⟨same_epoch, same_version, same_heard⟩ := current
  refine WP.spec_mono (delta_is s e t true) ?_
  rintro ⟨d, s1⟩ ⟨stale_is, _, add_is, _, moved⟩
  have fresh : ¬ (e = s.epoch ∧ t.val ≤ s.version.val) := by
    rw [same_version]; intro h; omega
  have added := add_is.mpr ⟨fresh, rfl⟩
  refine ⟨added, ?_⟩
  obtain ⟨epoch_is, version_is, heard_is⟩ := moved (by rw [added]; simp)
  refine WP.spec_mono (added_is s1 v t) ?_
  rintro s2 ⟨same_run, same_heard', applies, _⟩
  dsimp only at *
  have run : e = s.epoch := same_epoch.symm
  simp only [run, ite_true] at version_is heard_is
  have base : v = s1.version := UScalar.eq_equiv _ _ |>.mpr (by rw [version_is, same_version])
  have s2_heard : s2.heard = t := UScalar.eq_equiv _ _ |>.mpr (by
    rw [same_heard', heard_is, same_heard]; omega)
  exact ⟨⟨by rw [same_run]; exact epoch_is, applies ⟨base, nonzero⟩, s2_heard⟩, by
    unfold Behind; rw [applies ⟨base, nonzero⟩, s2_heard]; omega⟩

/-- The deltas that follow, one after the other, keep the filter current at the last version. -/
theorem following_deltas_keep_current (e : Std.U64) : ∀ (tos : List Std.U64) (v : Std.U64) (s : Seen),
    Current s e v → v.val ≠ 0 → Increasing v tos → Follow e v tos s ⦃ s' =>
      Current s' e (tos.getLastD v) ∧ ¬ Behind s' ⦄
  | [], v, s, current, _, _ => by
    unfold Follow
    refine (WP.spec_ok _).mpr ⟨current, ?_⟩
    obtain ⟨_, same_version, same_heard⟩ := current
    unfold Behind
    rw [same_version, same_heard]; omega
  | t :: ts, v, s, current, nonzero, ⟨later, increasing⟩ => by
    unfold Follow
    refine WP.spec_bind (a_following_delta_is_added s e v t current nonzero later) ?_
    rintro ⟨d, s1⟩ ⟨_, added⟩
    refine WP.spec_bind added ?_
    rintro s2 ⟨current', _⟩
    have last : (t :: ts).getLastD v = ts.getLastD t := by
      cases ts <;> simp [List.getLastD,]
    rw [last]
    exact following_deltas_keep_current e ts t s2 current' (by omega) increasing

/-- Proof of the first half of `AWholeFilterThenItsDeltasKeepTheFilterCurrent`: a whole filter that is not
older than what is held and heard is taken, and the `Seen` is current at its version. -/
theorem a_whole_filter_makes_the_filter_current (s : Seen) (e v : Std.U64) (held : Bool)
    (fresh : e ≠ s.epoch ∨ (s.version.val ≤ v.val ∧ s.heard.val ≤ v.val)) :
    Seen.full s e v held ⦃ a => a.1 = OnFull.Take ∧ Current a.2 e v ∧ ¬ Behind a.2 ⦄ := by
  refine WP.spec_mono (full_is s e v held) ?_
  rintro ⟨d, s1⟩ ⟨stale_is, _, taken⟩
  have not_stale : d ≠ OnFull.Stale := by
    intro stale
    obtain ⟨same, older, _⟩ := stale_is.mp stale
    rcases fresh with other | ⟨not_older, _⟩
    · exact other same
    · omega
  have take : d = OnFull.Take := by cases d <;> simp_all
  obtain ⟨epoch_is, version_is, heard_is⟩ := taken take
  dsimp only at *
  have heard_v : s1.heard.val = v.val := by
    rw [heard_is]
    by_cases same : e = s.epoch
    · rcases fresh with other | ⟨_, quiet⟩
      · exact absurd same other
      · simp [same]; omega
    · simp [same]
  refine ⟨take, ⟨epoch_is, version_is, UScalar.eq_equiv _ _ |>.mpr heard_v⟩, ?_⟩
  unfold Behind
  rw [version_is]; omega

/-- Proof of `AWholeFilterThenItsDeltasKeepTheFilterCurrent`: the two halves above. -/
theorem a_whole_filter_then_its_deltas_keep_the_filter_current :
    AWholeFilterThenItsDeltasKeepTheFilterCurrent :=
  ⟨a_whole_filter_makes_the_filter_current, fun s e v tos current nonzero increasing =>
    following_deltas_keep_current e tos v s current nonzero increasing⟩

end RecvCore
