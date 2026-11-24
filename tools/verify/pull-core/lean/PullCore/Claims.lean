-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `ALayerHasOneLiveClaimant` (Spec.lean): after any
-- call of the server, a table that was sound is sound: the pulls are numbered, no layer is
-- claimed by two claims, and the pull of a claim is held and not over.
--
-- Why it is needed: it is the claim of the crate that matters most for the server: two
-- pulls that need the same layer cannot both fetch it, and a pull that has ended (or was
-- forgotten) holds no layer, so it cannot keep another pull waiting for ever.
--
-- How it is proved: by cases on the call, each with what the files before this one say of its
-- function: Starts.lean (`begin`, `claim`, `forget`), Ends.lean (`end`) and Phases.lean (`staged`,
-- `commit`, `stop`).  For a claim to stay live after the call, its pull must not be moved to an
-- over phase while a claim of it is left: `end` and `forget` drop its claims, the others move it
-- to a phase that is not over (`sound_retag`).
--
-- Read before this file: Spec.lean, Table.lean, Starts.lean, Ends.lean and Phases.lean.
--
-- Notation: `List.Sublist` is "some elements of the list are left out"; `l.Nodup` is "no element
-- is twice in `l`"; `l.map f` is the list of the `f` of the elements of `l`; `⟨a, b, c⟩` builds
-- (or takes apart) a statement with three parts; `h.pull` is the pull of the claim `h`.
import Ok
import Models
import PullCore.Spec
import PullCore.Loops
import PullCore.Table
import PullCore.Ends
import PullCore.Starts
import PullCore.Phases

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

attribute [local irreducible] Ok

/-- A pull that has a phase that is not over is live. -/
theorem live_of_phase {c : Core} {q : Std.U32} {ph : Phase} (h : phaseOf c q = some ph)
    (not_over : ∀ o, ph ≠ Phase.Over o) : live c q := ⟨ph, h, not_over⟩

/-- What the pull dropped by a begin leaves of the table: some pulls, the claims of others,
and what the others are doing. -/
theorem dropped_facts {c c1 : Core} {old : Option Std.U32} (dropped : Dropped c old c1) :
    (∀ x ∈ c1.pulls.val, x ∈ c.pulls.val) ∧ c1.last = c.last ∧ c1.claims.val.Sublist c.claims.val ∧
    ∀ h ∈ c1.claims.val, phaseOf c1 h.pull = phaseOf c h.pull := by
  rcases dropped with rfl | ⟨o, -, forgotten⟩
  · exact ⟨fun _ hx => hx, rfl, List.Sublist.refl _, fun _ _ => rfl⟩
  · obtain ⟨hpulls, hclaims, hlast⟩ := forgotten
    refine ⟨fun x hx => by rw [hpulls] at hx; exact (List.mem_filter.mp hx).1, hlast, by
      rw [hclaims]; exact List.filter_sublist, fun h hmem => ?_⟩
    have not_o : h.pull ≠ o := kept_claim_of_other (by rwa [hclaims] at hmem)
    simp [phaseOf_forget ⟨hpulls, hclaims, hlast⟩ h.pull, not_o]

/-- A retag changes no number. -/
theorem numbered_retag {c c' : Core} {p : Std.U32} {ph : Phase} (retagged : Retag c c' p ph)
    (numbered : Numbered c) : Numbered c' := by
  obtain ⟨pre, q, post, hc, -, -, hc', hlast⟩ := retagged
  intro x hx
  rw [hc', List.mem_append, List.mem_cons] at hx
  rw [hlast]
  rcases hx with hx | rfl | hx
  · exact numbered x (by rw [hc]; simp [hx])
  · exact numbered q (by rw [hc]; simp)
  · exact numbered x (by rw [hc]; simp [hx])

/-- A retag to a phase that is not over, with the claims as they were, leaves a sound table. -/
theorem sound_retag {c c' : Core} {p : Std.U32} {ph : Phase} (sound : Sound c)
    (retagged : Retag c c' p ph) (claims : c'.claims = c.claims)
    (not_over : ∀ o, ph ≠ Phase.Over o) :
    Sound c' := by
  obtain ⟨numbered, distinct, owners⟩ := sound
  refine ⟨numbered_retag retagged numbered, by rw [claims]; exact distinct, ?_⟩
  intro h hmem
  rw [claims] at hmem
  rcases retag_cases retagged h.pull with same | ⟨rfl, moved⟩
  · obtain ⟨ph', hph', not_over'⟩ := owners h hmem
    exact ⟨ph', by rw [same, hph'], not_over'⟩
  · exact live_of_phase moved not_over

/-- **A layer has one claimant, and it is live** (`ALayerHasOneLiveClaimant` of Spec.lean).
The empty table is sound.  For a call, it goes through the seven calls of the server, one by
one: the calls that only move a pull (`staged`, `commit`, `stop`) leave the claims alone and move
a pull to a phase that is not over; `claim` adds the claims of a pull that now fetches, for layers
nobody claimed; `end` and `forget` drop the claims of the pull they end; `begin` forgets an old
pull with its claims, and pushes a new one that claims nothing. -/
theorem the_table_stays_sound : ALayerHasOneLiveClaimant := by
  refine ⟨fun c hp hc => ⟨by simp [Numbered, hp], by simp [hc], by simp [hc]⟩, ?_⟩
  intro c e c' sound each r
  cases e with
  | begin old =>
    -- the old pull of the name may be forgotten, with its claims; the new pull claims nothing
    obtain ⟨numbered, distinct, owners⟩ := sound
    obtain ⟨b, hr⟩ := r
    rcases Ok.eq (begin_spec c old) hr with rfl | ⟨c1, i, dropped, hi, hpulls, hclaims, hlast⟩
    · exact ⟨numbered, distinct, owners⟩
    · obtain ⟨members, same_last, sublist, same_phase⟩ := dropped_facts dropped
      refine ⟨?_, List.Nodup.sublist (List.Sublist.map _ (hclaims ▸ sublist)) distinct, ?_⟩
      · intro x hx
        rw [hpulls, List.mem_append, List.mem_singleton] at hx
        rw [hlast]
        rcases hx with hx | rfl
        · have := numbered x (members x hx)
          omega
        · exact Nat.le_refl _
      · intro h hmem
        rw [hclaims] at hmem
        obtain ⟨ph, hph, not_over⟩ := owners h (sublist.subset hmem)
        refine ⟨ph, ?_, not_over⟩
        rw [phaseOf_push hpulls h.pull, same_phase h hmem, hph]
  | claim p layers =>
    -- the pull now fetches, and claims layers that nobody had, each one once (`Each`)
    obtain ⟨a, hr⟩ := r
    have each' : layers.val.Nodup := each
    rcases Ok.eq (claim_spec c p layers) hr with rfl | ⟨waiting, free, retagged, claims⟩
    · exact sound
    · obtain ⟨numbered, distinct, owners⟩ := sound
      refine ⟨numbered_retag retagged numbered, ?_, ?_⟩
      · rw [claims, List.map_append, List.map_map]
        refine List.nodup_append.mpr ⟨distinct, ?_, ?_⟩
        · simp only [Function.comp_def, List.map_id']
          exact each'
        intro a ha b hb
        obtain ⟨h, hmem, rfl⟩ := List.mem_map.mp ha
        obtain ⟨l, hl, rfl⟩ := List.mem_map.mp hb
        exact free l hl h hmem
      · intro h hmem
        rw [claims, List.mem_append] at hmem
        rcases hmem with old | new
        · rcases retag_cases retagged h.pull with same | ⟨rfl, moved⟩
          · obtain ⟨ph', hph', not_over'⟩ := owners h old
            exact ⟨ph', by rw [same, hph'], not_over'⟩
          · exact live_of_phase moved (by simp)
        · obtain ⟨l, -, rfl⟩ := List.mem_map.mp new
          exact live_of_phase (ph := Phase.Fetching) (by simp [phaseOf_retag retagged]) (by simp)
  | staged p =>
    -- `staged`, `commit` and `stop` move a pull to a phase that is not over; the claims stay
    obtain ⟨a, hr⟩ := r
    rcases Ok.eq (staged_spec c p) hr with rfl | ⟨-, retagged, claims⟩
    · exact sound
    · exact sound_retag sound retagged claims (by simp)
  | commit p =>
    obtain ⟨a, hr⟩ := r
    rcases Ok.eq (commit_spec c p) hr with rfl | ⟨-, retagged, claims⟩
    · exact sound
    · exact sound_retag sound retagged claims (by simp)
  | stop p why =>
    rcases Ok.eq (stop_spec c p why) r with rfl | ⟨-, retagged, claims⟩
    · exact sound
    · exact sound_retag sound retagged claims (by simp)
  | finish p published =>
    -- the claims of the pull go, and the other pulls are as they were
    obtain ⟨numbered, distinct, owners⟩ := sound
    obtain ⟨hlast, hclaims, hretag, habsent⟩ := Ok.eq (end_spec c p published) r
    have sublist : c'.claims.val.Sublist c.claims.val := by rw [hclaims]; exact List.filter_sublist
    have unchanged : ∀ q, q ≠ p → phaseOf c' q = phaseOf c q := by
      intro q hq
      cases hp : phaseOf c p with
      | none => exact phaseOf_congr (habsent hp) q
      | some ph => simpa [hq] using phaseOf_retag (hretag ph hp) q
    refine ⟨?_, List.Nodup.sublist (List.Sublist.map _ sublist) distinct, ?_⟩
    · cases hp : phaseOf c p with
      | none =>
        intro x hx
        rw [hlast]
        exact numbered x (by rw [← habsent hp]; exact hx)
      | some ph => exact numbered_retag (hretag ph hp) numbered
    · intro h hmem
      have not_p : h.pull ≠ p := kept_claim_of_other (by rwa [hclaims] at hmem)
      obtain ⟨ph, hph, not_over⟩ := owners h (sublist.subset hmem)
      exact ⟨ph, by rw [unchanged _ not_p, hph], not_over⟩
  | forget p =>
    -- the same, for the pull that is dropped
    obtain ⟨numbered, distinct, owners⟩ := sound
    obtain ⟨hpulls, hclaims, hlast⟩ := Ok.eq (forget_spec c p) r
    have sublist : c'.claims.val.Sublist c.claims.val := by rw [hclaims]; exact List.filter_sublist
    refine ⟨?_, List.Nodup.sublist (List.Sublist.map _ sublist) distinct, ?_⟩
    · intro x hx
      rw [hpulls] at hx
      rw [hlast]
      exact numbered x (List.mem_filter.mp hx).1
    · intro h hmem
      have not_p : h.pull ≠ p := kept_claim_of_other (by rwa [hclaims] at hmem)
      obtain ⟨ph, hph, not_over⟩ := owners h (sublist.subset hmem)
      exact ⟨ph, by simp [phaseOf_forget ⟨hpulls, hclaims, hlast⟩ h.pull, not_p, hph], not_over⟩

end PullCore
