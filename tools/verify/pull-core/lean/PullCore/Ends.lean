-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `AnEndFreesTheClaimsOnce` (Spec.lean): when a pull ends
-- (the task finished, failed or was stopped) its layers are free, and ending it again does
-- not change the core.
--
-- Why it is needed: the shell calls `end` when the task of a pull is over, and may call it
-- twice (the task that was told to stop, and the call that sees the pull gone).  A claim that
-- stayed after the end would keep every later pull of the layer waiting for ever, and a second
-- end that changed the outcome would turn a published pull into a failed one.
--
-- How it is proved: `end_spec` says what `end` does, following the Rust line by line (the pull
-- is found, its phase is set, the claims of the pull are dropped with `retain`); the claim is
-- then read off it, for the first end and for the second.  Claims.lean and Phases.lean use
-- `end_spec` too, and Claims.lean `kept_claim_of_other` (for `forget` as well).
--
-- Read before this file: Spec.lean and Table.lean.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `∀`, `∃` and `→` as in
-- Spec.lean; `c''` is the core after the second call.
import Ok
import Models
import PullCore.Spec
import PullCore.Loops
import PullCore.Table

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

attribute [local irreducible] Ok

/-- The phase a pull has once it ended (`Core::end`), when the shell says it `published`
or not: a committing pull that was published is published (`Over none`), a stopping one is
over for its reason, any other is over as failed; an over pull stays as it is. -/
def outcome (ph : Phase) (published : Bool) : Phase :=
  match ph with
  | Phase.Committing => if published then Phase.Over none else Phase.Over (some Why.Failed)
  | Phase.Stopping why => Phase.Over (some why)
  | Phase.Over o => Phase.Over o
  | _ => Phase.Over (some Why.Failed)

/-- A pull that ends is over, whatever it was doing. -/
theorem outcome_over (ph : Phase) (published : Bool) :
    ∃ o, outcome ph published = Phase.Over o := by
  cases ph <;> simp only [outcome] <;> first | exact ⟨_, rfl⟩ | (split <;> exact ⟨_, rfl⟩)

/-- A claim that the `retain` of `end` or `forget` keeps is of another pull than `p`. -/
theorem kept_claim_of_other {l : List Held} {p : Std.U32} {h : Held}
    (kept : h ∈ l.filter (fun h => h.pull != p)) : h.pull ≠ p := by
  simpa using (List.mem_filter.mp kept).2

/-- `end`: the claims are those of the other pulls; a pull the core holds has the phase
`outcome` says (the same pulls otherwise), and the last number is the same. -/
theorem end_spec (c : Core) (p : Std.U32) (published : Bool) :
    Ok (Core.end c p published) (fun c' =>
      c'.last = c.last ∧ c'.claims.val = c.claims.val.filter (fun h => h.pull != p) ∧
      (∀ ph, phaseOf c p = some ph → Retag c c' p (outcome ph published)) ∧
      (phaseOf c p = none → c'.pulls = c.pulls)) := by
  unfold Core.end
  refine Ok.bind (pull_at_spec c p) ?_
  intro o found
  refine Ok.bind (Q := fun c1 => c1.last = c.last ∧ c1.claims = c.claims ∧
    (∀ ph, phaseOf c p = some ph → Retag c c1 p (outcome ph published)) ∧
    (phaseOf c p = none → c1.pulls = c.pulls)) ?_ ?_
  · cases o with
    | none =>
      exact Ok.ok.mpr ⟨rfl, rfl, by simp [phaseOf_absent found], fun _ => rfl⟩
    | some i =>
      obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
      dsimp only
      refine Ok.bind (found_index hc hi) ?_
      intro x hx
      subst hx
      have set : ∀ ph, Ok (do
          let (p2, back) ← alloc.vec.Vec.index_mut
            (core.slice.index.SliceIndexUsizeSlice Pull) c.pulls i
          ok (back { p2 with phase := ph }))
          (fun v => Retag c { c with pulls := v } p ph) := by
        intro ph
        refine Ok.bind (found_set hc hq hpre hi ph) ?_
        rintro ⟨y, back⟩ ⟨hy, retagged⟩
        dsimp only at hy retagged
        subst hy
        exact Ok.ok.mpr retagged
      have done : ∀ v, Retag c { c with pulls := v } p (outcome x.phase published) →
          ({ c with pulls := v } : Core).last = c.last ∧
          ({ c with pulls := v } : Core).claims = c.claims ∧
          (∀ ph, phaseOf c p = some ph → Retag c { c with pulls := v } p (outcome ph published)) ∧
          (phaseOf c p = none → ({ c with pulls := v } : Core).pulls = c.pulls) := by
        intro v retagged
        refine ⟨rfl, rfl, fun ph hph => ?_, fun absent => ?_⟩
        · rw [phaseOf_found hc hq hpre, Option.some.injEq] at hph
          rw [← hph]; exact retagged
        · rw [phaseOf_found hc hq hpre] at absent; simp at absent
      cases hph : x.phase
      · exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
      · exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
      · exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
      · cases published
        · simp only [Bool.false_eq_true, ↓reduceIte]
          exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
        · simp only [↓reduceIte]
          exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
      · exact Ok.bind (set _) (fun v hv => Ok.ok.mpr (done v (by simpa [outcome, hph] using hv)))
      · rename_i o
        simp only [bind_ok]
        apply Ok.ok.mpr
        refine done c.pulls ⟨pre, x, post, hc, hq, hpre, ?_, rfl⟩
        have same : ({ x with phase := Phase.Over o } : Pull) = x := by cases x; simp_all
        simp [outcome, hph, same, hc]
  · intro c1 ⟨hlast, hclaims, hphase, habsent⟩
    refine Ok.bind (retain_filter _ (fun h => h.pull != p) p (fun h => rfl) c1.claims) ?_
    intro v hv
    apply Ok.ok.mpr
    refine ⟨hlast, by rw [hv, hclaims], ?_, ?_⟩
    · intro ph hph
      obtain ⟨pre, q, post, hc, hq, hpre, hc', hl⟩ := hphase ph hph
      exact ⟨pre, q, post, hc, hq, hpre, hc', hlast⟩
    · intro absent
      exact habsent absent

/-- **An end frees the claims, and a second end changes nothing** (`AnEndFreesTheClaimsOnce` of
Spec.lean).  `end_spec` says the claims after an end are those of the other pulls, and the
pull is over, as `outcome` says.  A second end then finds the pull over (`outcome` of an over
phase is that phase), so the pulls stay, and finds no claim of it, so the claims stay. -/
theorem an_end_frees_the_claims_once : AnEndFreesTheClaimsOnce := by
  intro c p published c' hend
  obtain ⟨hlast, hclaims, hretag, habsent⟩ := Ok.eq (end_spec c p published) hend
  have no_claim : ∀ h ∈ c'.claims.val, h.pull ≠ p := fun h hmem =>
    kept_claim_of_other (by rwa [hclaims] at hmem)
  refine ⟨no_claim, ?_, ?_⟩
  · intro ph hph
    obtain ⟨o, ho⟩ := outcome_over ph published
    exact ⟨o, by rw [phaseOf_retag (hretag ph hph) p, ← ho]; simp⟩
  · intro published' c'' hend'
    obtain ⟨hlast', hclaims', hretag', habsent'⟩ := Ok.eq (end_spec c' p published') hend'
    -- nothing changes: the claims, the last number, and the pulls
    have same_claims : c''.claims.val = c'.claims.val := by
      rw [hclaims', List.filter_eq_self]
      intro h hmem
      simpa using no_claim h hmem
    have same_pulls : c''.pulls = c'.pulls := by
      cases hp : phaseOf c p with
      | none => exact habsent' (by rw [phaseOf_congr (habsent hp), hp])
      | some ph =>
        obtain ⟨o, ho⟩ := outcome_over ph published
        have over : phaseOf c' p = some (Phase.Over o) := by
          rw [phaseOf_retag (hretag ph hp) p, ← ho]; simp
        obtain ⟨pre, q, post, hc, hq, hpre, hc'', -⟩ := hretag' _ over
        have phase : q.phase = Phase.Over o := by
          simpa [phaseOf_found hc hq hpre] using over
        have same : ({ q with phase := outcome (Phase.Over o) published' } : Pull) = q := by
          obtain ⟨id, phase'⟩ := q
          simp_all [outcome]
        apply alloc.vec.Vec.ext
        rw [hc'', hc, same]
    obtain ⟨pulls', claims', last'⟩ := c''
    obtain ⟨pulls, claims, last⟩ := c'
    simp only [Core.mk.injEq] at *
    exact ⟨same_pulls, alloc.vec.Vec.ext _ _ same_claims, hlast'⟩

end PullCore
