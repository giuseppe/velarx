-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `APullIsPublishedOnlyFromCommitting` and
-- `TheFirstDecisionStands` (Spec.lean): the server publishes the layers of a pull only after
-- the engine committed it, and the first decision of a pull (to stop for a reason, to commit)
-- is the one that counts.
--
-- Why it is needed: before the core, an Abort that came after a Commit overwrote it and the
-- aborted pull was published, a Commit that came after an Abort overwrote it, and a pull could
-- be committed before it had fetched.  These are the claims that, whatever the order of the
-- calls, none of that can happen.
--
-- How they are proved: this file says what `asked`, `staged`, `commit` and `stop` do, the
-- functions that move a pull from one phase to the next (`asked_spec`, `staged_spec`,
-- `commit_spec`, `stop_spec`), following their Rust line by line.  With what Ends.lean and
-- Starts.lean say of the other calls, `phases_move` tells, for any call, how the phase of a
-- pull stays or moves (`Moves`); the two claims are read off it, a case for each call
-- (`simp [hy]`: a pull that is staged is not published).
--
-- Read before this file: Spec.lean, Table.lean, Ends.lean and Starts.lean.
--
-- Notation: `Moves e q x y` reads "when the call `e` is made, the phase of the pull `q` may go
-- from `x` to `y`" (`x` and `y` are `none` for no such pull); `rcases a with b | c` takes the
-- cases of an "or"; `obtain ⟨x, h⟩ := a` takes apart an "and"/"there is"; `-` throws a part
-- away; `simp [hy]` uses the equation `hy` to rewrite and close a goal.
import Ok
import Models
import PullCore.Spec
import PullCore.Loops
import PullCore.Table
import PullCore.Ends
import PullCore.Starts

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

attribute [local irreducible] Ok

/-- `asked` says to publish only for a pull that is committing. -/
theorem asked_spec (c : Core) (p : Std.U32) :
    Ok (Core.asked c p) (fun a => a = Asked.Publish → phaseOf c p = some Phase.Committing) := by
  unfold Core.asked
  refine Ok.bind (phase_spec c p) ?_
  intro o ho
  subst ho
  rcases hph : phaseOf c p with _ | ph
  · exact Ok.ok.mpr (by simp)
  · cases ph <;> first
      | exact Ok.ok.mpr (by simp)
      | (rename_i o; cases o <;> exact Ok.ok.mpr (by simp))

/-- `staged`: it leaves the core as it was, or the pull was fetching and is staged. -/
theorem staged_spec (c : Core) (p : Std.U32) :
    Ok (Core.staged c p) (fun r =>
      r.2 = c ∨ (phaseOf c p = some Phase.Fetching ∧ Retag c r.2 p Phase.Staged ∧
        r.2.claims = c.claims)) := by
  unfold Core.staged
  refine Ok.bind (pull_at_spec c p) ?_
  rintro (_ | i) found
  · exact Ok.ok.mpr (Or.inl rfl)
  · obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
    refine Ok.bind (found_index hc hi) ?_
    intro x hx
    subst hx
    refine Ok.bind (phase_eq x.phase Phase.Fetching (Or.inr rfl)) ?_
    intro b hb
    split
    · rename_i fetching
      refine Ok.bind (found_set hc hq hpre hi Phase.Staged) ?_
      rintro ⟨y, back⟩ ⟨hy, retagged⟩
      dsimp only at hy retagged
      subst hy
      exact Ok.ok.mpr (Or.inr ⟨by rw [phaseOf_found hc hq hpre, hb.mp fetching], retagged, rfl⟩)
    · exact Ok.ok.mpr (Or.inl rfl)

/-- `commit`: it leaves the core as it was, or the pull was staged and is committing. -/
theorem commit_spec (c : Core) (p : Std.U32) :
    Ok (Core.commit c p) (fun r =>
      r.2 = c ∨ (phaseOf c p = some Phase.Staged ∧ Retag c r.2 p Phase.Committing ∧
        r.2.claims = c.claims)) := by
  unfold Core.commit
  refine Ok.bind (pull_at_spec c p) ?_
  rintro (_ | i) found
  · exact Ok.ok.mpr (Or.inl rfl)
  · obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
    refine Ok.bind (found_index hc hi) ?_
    intro x hx
    subst hx
    cases hph : x.phase
    · exact Ok.ok.mpr (Or.inl rfl)
    · exact Ok.ok.mpr (Or.inl rfl)
    · refine Ok.bind (found_set hc hq hpre hi Phase.Committing) ?_
      rintro ⟨y, back⟩ ⟨hy, retagged⟩
      dsimp only at hy retagged
      subst hy
      exact Ok.ok.mpr (Or.inr ⟨by rw [phaseOf_found hc hq hpre, hph], retagged, rfl⟩)
    all_goals exact Ok.ok.mpr (Or.inl rfl)

/-- `stop`: it leaves the core as it was, or the pull was waiting, fetching or staged and
is stopping, for the reason given. -/
theorem stop_spec (c : Core) (p : Std.U32) (why : Why) :
    Ok (Core.stop c p why) (fun c' => c' = c ∨
      ((phaseOf c p = some Phase.Waiting ∨ phaseOf c p = some Phase.Fetching ∨
        phaseOf c p = some Phase.Staged) ∧ Retag c c' p (Phase.Stopping why) ∧
        c'.claims = c.claims)) := by
  unfold Core.stop
  refine Ok.bind (pull_at_spec c p) ?_
  rintro (_ | i) found
  · exact Ok.ok.mpr (Or.inl rfl)
  · obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
    refine Ok.bind (found_index hc hi) ?_
    intro x hx
    subst hx
    -- the pull is stoppable in three phases (the match of the Rust gives `true` for them)
    have stops : (x.phase = Phase.Waiting ∨ x.phase = Phase.Fetching ∨ x.phase = Phase.Staged) →
        Ok (do
          let (p2, back) ← alloc.vec.Vec.index_mut
            (core.slice.index.SliceIndexUsizeSlice Pull) c.pulls i
          ok { c with pulls := back { p2 with phase := Phase.Stopping why } })
        (fun c' => c' = c ∨ ((phaseOf c p = some Phase.Waiting ∨ phaseOf c p = some Phase.Fetching ∨
          phaseOf c p = some Phase.Staged) ∧ Retag c c' p (Phase.Stopping why) ∧
          c'.claims = c.claims)) := by
      intro stoppable
      refine Ok.bind (found_set hc hq hpre hi (Phase.Stopping why)) ?_
      rintro ⟨y, back⟩ ⟨hy, retagged⟩
      dsimp only at hy retagged
      subst hy
      refine Ok.ok.mpr (Or.inr ⟨?_, retagged, rfl⟩)
      rw [phaseOf_found hc hq hpre]
      simpa using stoppable
    cases hph : x.phase
    · simpa using stops (Or.inl hph)
    · simpa using stops (Or.inr (Or.inl hph))
    · simpa using stops (Or.inr (Or.inr hph))
    all_goals simpa using (Ok.ok.mpr (Or.inl rfl) : Ok (ok c) (fun c' => c' = c ∨ _))

/-- How the phase of a pull may move when the call `e` is made: `x` before, `y` after.
Only the pull the call is about moves (and a begin starts one, and forgets the one it
replaces), by one step the call makes. -/
def Moves (e : Event) (q : Std.U32) (x y : Option Phase) : Prop :=
  match e with
  | .begin old => (x = none ∧ y = some Phase.Waiting) ∨ (∃ o, old = some o ∧ q = o ∧ y = none)
  | .claim p _ => q = p ∧ x = some Phase.Waiting ∧ y = some Phase.Fetching
  | .staged p => q = p ∧ x = some Phase.Fetching ∧ y = some Phase.Staged
  | .commit p => q = p ∧ x = some Phase.Staged ∧ y = some Phase.Committing
  | .stop p why => q = p ∧
      (x = some Phase.Waiting ∨ x = some Phase.Fetching ∨ x = some Phase.Staged) ∧
      y = some (Phase.Stopping why)
  | .finish p published => q = p ∧ ∃ ph, x = some ph ∧ y = some (outcome ph published)
  | .forget p => q = p ∧ y = none

/-- A pull the core holds is numbered, so it is not above `last`. -/
theorem numbered_of_phaseOf {c : Core} (numbered : Numbered c) {q : Std.U32} {ph : Phase}
    (held : phaseOf c q = some ph) : q.val ≤ c.last.val := by
  obtain ⟨x, found, -⟩ := Option.map_eq_some_iff.mp held
  have : x.id = q := by simpa using List.find?_some found
  rw [← this]
  exact numbered x (List.mem_of_find?_eq_some found)

/-- **Whatever the call, the phase of a pull stays or moves as the call says.**  For a core
whose pulls are numbered (`Numbered`: a new pull gets a number nobody has), after any call
that returns, each pull has the phase it had or one that the call moves it to (`Moves`). -/
theorem phases_move {c c' : Core} {e : Event} (numbered : Numbered c) (r : runs c e c')
    (q : Std.U32) :
    phaseOf c' q = phaseOf c q ∨ Moves e q (phaseOf c q) (phaseOf c' q) := by
  cases e with
  | begin old =>
    -- `begin`: nothing changes, or the old pull goes and the new one is pushed
    obtain ⟨b, hr⟩ := r
    have spec := Ok.eq (begin_spec c old) hr
    dsimp only at spec
    rcases spec with rfl | ⟨c1, i, dropped, hi, hpulls, -, -⟩
    · exact Or.inl rfl
    · have pushed := phaseOf_push hpulls q
      -- (a pull that is held is numbered below the new one, so it is not the new one)
      have fresh : ∀ ph, phaseOf c q = some ph → i ≠ q := fun ph held h => by
        have := numbered_of_phaseOf numbered held
        subst h
        omega
      rcases dropped with rfl | ⟨o, hold, forgotten⟩
      · -- nothing was forgotten: the pull is as it was, or it is the new one
        cases hq : phaseOf c1 q with
        | some ph => exact Or.inl (by rw [pushed, hq])
        | none =>
          rw [hq] at pushed
          by_cases hiq : i = q
          · subst hiq; exact Or.inr (Or.inl ⟨rfl, by simpa using pushed⟩)
          · exact Or.inl (by rw [pushed]; simp [hiq])
      · -- the old pull `o` was forgotten
        have gone := phaseOf_forget forgotten q
        by_cases hqo : q = o
        · subst hqo
          have unseen : phaseOf c1 q = none := by simp [gone]
          rw [unseen] at pushed
          cases hq : phaseOf c q with
          | none =>
            by_cases hiq : i = q
            · subst hiq; exact Or.inr (Or.inl ⟨rfl, by simpa using pushed⟩)
            · exact Or.inl (by rw [pushed]; simp [hiq])
          | some ph =>
            exact Or.inr (Or.inr ⟨q, hold, rfl, by rw [pushed]; simp [fresh ph hq]⟩)
        · have same : phaseOf c1 q = phaseOf c q := by simp [gone, hqo]
          rw [same] at pushed
          cases hq : phaseOf c q with
          | some ph => exact Or.inl (by rw [pushed, hq])
          | none =>
            rw [hq] at pushed
            by_cases hiq : i = q
            · subst hiq; exact Or.inr (Or.inl ⟨rfl, by simpa using pushed⟩)
            · exact Or.inl (by rw [pushed]; simp [hiq])
  -- the other calls retag the pull they are about (or end it), and no other
  | claim p layers =>
    obtain ⟨a, hr⟩ := r
    have spec := Ok.eq (claim_spec c p layers) hr
    dsimp only at spec
    rcases spec with rfl | ⟨waiting, free, retagged, claims⟩
    · exact Or.inl rfl
    · rcases retag_cases retagged q with same | ⟨rfl, moved⟩
      · exact Or.inl same
      · exact Or.inr ⟨rfl, waiting, moved⟩
  | staged p =>
    obtain ⟨a, hr⟩ := r
    have spec := Ok.eq (staged_spec c p) hr
    dsimp only at spec
    rcases spec with rfl | ⟨fetching, retagged, claims⟩
    · exact Or.inl rfl
    · rcases retag_cases retagged q with same | ⟨rfl, moved⟩
      · exact Or.inl same
      · exact Or.inr ⟨rfl, fetching, moved⟩
  | commit p =>
    obtain ⟨a, hr⟩ := r
    have spec := Ok.eq (commit_spec c p) hr
    dsimp only at spec
    rcases spec with rfl | ⟨staged, retagged, claims⟩
    · exact Or.inl rfl
    · rcases retag_cases retagged q with same | ⟨rfl, moved⟩
      · exact Or.inl same
      · exact Or.inr ⟨rfl, staged, moved⟩
  | stop p why =>
    have spec := Ok.eq (stop_spec c p why) r
    rcases spec with rfl | ⟨stoppable, retagged, claims⟩
    · exact Or.inl rfl
    · rcases retag_cases retagged q with same | ⟨rfl, moved⟩
      · exact Or.inl same
      · exact Or.inr ⟨rfl, stoppable, moved⟩
  | finish p published =>
    have spec := Ok.eq (end_spec c p published) r
    obtain ⟨-, -, retagged, absent⟩ := spec
    cases hp : phaseOf c p with
    | none => exact Or.inl (by simp [phaseOf, absent hp])
    | some ph =>
      rcases retag_cases (retagged ph hp) q with same | ⟨rfl, moved⟩
      · exact Or.inl same
      · exact Or.inr ⟨rfl, ph, hp, moved⟩
  | forget p =>
    have spec := Ok.eq (forget_spec c p) r
    by_cases hq : q = p
    · subst hq; exact Or.inr ⟨rfl, by rw [phaseOf_forget spec]; simp⟩
    · exact Or.inl (by simp [phaseOf_forget spec q, hq])

/-- A pull that ends is over as published only if it was committing and the shell said it
published (or it was published already). -/
theorem outcome_published {ph : Phase} {published : Bool}
    (h : outcome ph published = Phase.Over none) :
    ph = Phase.Over none ∨ (ph = Phase.Committing ∧ published = true) := by
  cases ph <;> cases published <;> simp_all [outcome]

/-- **A pull is published only from committing** (`APullIsPublishedOnlyFromCommitting` of
Spec.lean).  `asked` says to publish only for a committing pull (`asked_spec`).  For a call,
the phase of the pull after it is, by `phases_move`, the one it had or the one the call moves it
to: only `end` of a committing pull, told it was published, moves a pull to published, and only
`commit` of a staged pull moves a pull to committing; no other call moves a pull to either. -/
theorem a_pull_is_published_only_from_committing : APullIsPublishedOnlyFromCommitting := by
  refine ⟨fun c p asked => Ok.eq (asked_spec c p) asked rfl, ?_⟩
  intro c e c' q numbered r
  rcases phases_move numbered r q with same | moved
  · exact ⟨fun h => Or.inl (same ▸ h), fun h => Or.inl (same ▸ h)⟩
  · cases e with
    | finish p published =>
      obtain ⟨rfl, ph, hx, hy⟩ := moved
      obtain ⟨o, ho⟩ := outcome_over ph published
      refine ⟨fun h => ?_, fun h => ?_⟩
      · rcases outcome_published (by simpa [hy] using h) with over | ⟨committing, pub⟩
        · exact Or.inl (by rw [hx, over])
        · exact Or.inr ⟨by rw [hx, committing], by rw [pub]⟩
      · simp [hy, ho] at h
    | commit p =>
      obtain ⟨rfl, hx, hy⟩ := moved
      exact ⟨by simp [hy], fun _ => Or.inr ⟨hx, rfl⟩⟩
    | begin old =>
      rcases moved with ⟨-, hy⟩ | ⟨-, -, -, hy⟩ <;> simp [hy]
    | claim p layers => obtain ⟨-, -, hy⟩ := moved; simp [hy]
    | staged p => obtain ⟨-, -, hy⟩ := moved; simp [hy]
    | stop p why => obtain ⟨-, -, hy⟩ := moved; simp [hy]
    | forget p => obtain ⟨-, hy⟩ := moved; simp [hy]

/-- **The first decision stands** (`TheFirstDecisionStands` of Spec.lean).  After a call a
pull that was stopping for `w` is stopping for `w`, or over for `w`, or forgotten; a pull that
was committing is committing, over or forgotten.  By `phases_move`: the phase stays, or the call
moves it; the calls that move a pull away from `stopping` or from `committing` are only `end` (to
an over phase, which for a stopping pull is over with its reason, by `outcome`) and `forget` (the
pull is gone), and `stop`, `claim`, `staged` and `commit` are made on pulls that are in neither
phase. -/
theorem the_first_decision_stands : TheFirstDecisionStands := by
  intro c e c' q numbered r
  rcases phases_move numbered r q with same | moved
  · exact ⟨fun w h => Or.inl (by rw [same]; exact h), fun h => Or.inl (by rw [same]; exact h)⟩
  · cases e with
    | finish p published =>
      obtain ⟨rfl, ph, hx, hy⟩ := moved
      refine ⟨fun w h => ?_, fun h => ?_⟩
      · rw [hx, Option.some.injEq] at h
        subst h
        exact Or.inr (Or.inl (by simp [hy, outcome]))
      · rw [hx, Option.some.injEq] at h
        obtain ⟨o, ho⟩ := outcome_over ph published
        exact Or.inr (Or.inl ⟨o, by rw [hy, ho]⟩)
    | forget p => obtain ⟨-, hy⟩ := moved; simp [hy]
    | begin old =>
      rcases moved with ⟨hx, -⟩ | ⟨-, -, -, hy⟩ <;> simp [*]
    | claim p layers => obtain ⟨-, hx, -⟩ := moved; simp [hx]
    | staged p => obtain ⟨-, hx, -⟩ := moved; simp [hx]
    | commit p => obtain ⟨-, hx, -⟩ := moved; simp [hx]
    | stop p why =>
      obtain ⟨-, hx, -⟩ := moved
      rcases hx with hx | hx | hx <;> simp [hx]

end PullCore
