-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `mirrored` answers for one mirror of a block: nothing when the mirror
-- does not serve the request or the block chosen for its address is blocked; the refusal
-- `NoRepository` when its address has no `/`; else its endpoint, at that address, with its own
-- flags, the credentials of the command line only for the host that was named, and `by_digest`
-- exactly for a mirror for digests only.
-- Why it is needed: `endpoints` calls `mirrored` for each mirror of the chosen block, and the
-- claims about the list, the flags and the refusals are read from what it answers.
-- Read before this file: Spec.lean, RewritesOfNames.lean, EndpointAtAnAddress.lean,
-- SelectChoosesTheBlock.lean, BlockedAndPrivateAt.lean, MirrorFieldsAreRead.lean.
-- Notation: `step with t as ⟨ x, hx ⟩` runs one line of a Rust function with the theorem `t` and
-- names its result `x` and what is known of it `hx`.
import EndpointCore.Spec
import EndpointCore.RewritesOfNames
import EndpointCore.EndpointAtAnAddress
import EndpointCore.SelectChoosesTheBlock
import EndpointCore.BlockedAndPrivateAt
import EndpointCore.MirrorFieldsAreRead
import EndpointCore.VectorsAreSlices

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- What `mirrored` answers for the mirror `mir` of `block`, for the name `ref` and the host the
user named `host`: one of four cases. -/
def MirrorAnswers (blocks : List Block) (block : Block) (mir : Mirror) (ask : Ask)
    (ref host : Bytes) (r : core.result.Result (Option Endpoint) Refused) : Prop :=
  (¬ Serves mir.mode ask.has_digest ∧ r = .Ok none) ∨
  (Serves mir.mode ask.has_digest ∧ BlockedAt blocks (MirrorAddress block mir ref) ∧
    r = .Ok none) ∨
  (Serves mir.mode ask.has_digest ∧ ¬ BlockedAt blocks (MirrorAddress block mir ref) ∧
    Slash ∉ MirrorAddress block mir ref ∧ r = .Err .NoRepository) ∨
  (Serves mir.mode ask.has_digest ∧ ¬ BlockedAt blocks (MirrorAddress block mir ref) ∧
    ∃ e, Slash ∈ MirrorAddress block mir ref ∧ r = .Ok (some e) ∧
      Located (MirrorAddress block mir ref) = some e.Where ∧
      (e.insecure = true ↔ mir.insecure = true ∨ ask.tls_verify = false) ∧
      (e.allow_private = true ↔
        block.allow_private = true ∨ AllowsPrivateAt blocks (MirrorAddress block mir ref)) ∧
      (e.creds = Creds.CommandLine ↔ e.host.val = Folded host) ∧
      (e.by_digest = true ↔ mir.mode = Mode.DigestOnly))

/-- **`mirrored`** answers for the mirror number `m` of the block number `b` as `MirrorAnswers`
says. -/
theorem mirrored_answers_for_its_mirror (blocks : Slice Block) (b m : Std.Usize)
    (ref host : Slice Std.U8) (ask : Ask) (block : Block) (mir : Mirror)
    (is_block : blocks.val[b.val]? = some block) (is_mirror : block.mirrors.val[m.val]? = some mir)
    (room : mir.location.length + ref.length ≤ Std.Usize.max) :
    mirrored blocks b m ref host ask ⦃ r =>
      MirrorAnswers blocks.val block mir ask ref.val host.val r ⦄ := by
  unfold mirrored
  step with mirror_mode_reads_the_mode blocks b m block mir is_block is_mirror as ⟨ mode, is_mode ⟩
  step with serves_says_the_mode_serves as ⟨ does_serve, does_serve_says ⟩
  by_cases serving : does_serve = true
  · simp only [serving, ite_true]
    have serves : Serves mir.mode ask.has_digest := by
      rw [← is_mode]
      exact does_serve_says.mp serving
    step with mirror_insecure_reads_the_flag blocks b m block mir is_block is_mirror as
      ⟨ own_insecure, is_own_insecure ⟩
    refine WP.spec_bind (Pₘ := fun insecure : Bool =>
      insecure = true ↔ mir.insecure = true ∨ ask.tls_verify = false) ?_ ?_
    · by_cases own : own_insecure = true
      · simp only [own, ite_true]
        refine (WP.spec_ok _).mpr ?_
        simp [is_own_insecure] at own
        simp [own]
      · have not_own : own_insecure = false := by simpa using own
        simp only [not_own, Bool.false_eq_true, ↓reduceIte]
        step with unverified_says_verification_is_off as ⟨ off, off_says ⟩
        simp [off_says, ← is_own_insecure, not_own]
    · intro insecure insecure_says
      have room' : mir.location.length + ref.length ≤ Std.Usize.max := room
      step with moved_is_the_address_of_the_mirror blocks b m ref block mir is_block is_mirror room'
        as ⟨ there, is_there ⟩
      step with select_chooses_the_block as ⟨ own, own_chooses ⟩
      have address_is : MirrorAddress block mir ref.val = there.val := by
        rw [is_there]
        rfl
      have own_chooses' : Chooses blocks.val (MirrorAddress block mir ref.val)
          (own.map (·.val)) := by
        rw [address_is]
        simpa using own_chooses
      step with blocked_says_the_block_is_blocked blocks own _ own_chooses' as
        ⟨ is_blocked, is_blocked_says ⟩
      by_cases blocked_here : is_blocked = true
      · simp only [blocked_here, ite_true]
        refine (WP.spec_ok _).mpr (Or.inr (Or.inl ⟨serves, is_blocked_says.mp blocked_here, rfl⟩))
      · have not_blocked : is_blocked = false := by simpa using blocked_here
        simp only [not_blocked, Bool.false_eq_true, ↓reduceIte]
        have free : ¬ BlockedAt blocks.val (MirrorAddress block mir ref.val) :=
          fun is_blocked_here => blocked_here (is_blocked_says.mpr is_blocked_here)
        have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
        step as ⟨ blk, is_blk ⟩
        have blk_is : blk = block := by
          have := List.getElem?_eq_getElem inside
          rw [is_block] at this
          simp [is_blk, Option.some.inj this]
        subst blk_is
        refine WP.spec_bind (Pₘ := fun reach : Bool =>
          reach = true ↔ blk.allow_private = true ∨
            AllowsPrivateAt blocks.val (MirrorAddress blk mir ref.val)) ?_ ?_
        · by_cases own_private : blk.allow_private = true
          · simp only [own_private, ite_true]
            refine (WP.spec_ok _).mpr ?_
            simp
          · have not_private : blk.allow_private = false := by simpa using own_private
            simp only [not_private, Bool.false_eq_true, ↓reduceIte]
            step with allows_private_says_the_block_allows_it blocks own _ own_chooses' as
              ⟨ allowed, allowed_says ⟩
            simp [allowed_says]
        · intro reach reach_says
          step with at_makes_the_endpoint_of_an_address as ⟨ o, o_says ⟩
          rcases o_says with ⟨no_slash, is_none⟩ | ⟨e, has_slash, is_some, located, e_insecure,
            e_reach, e_creds, e_digest⟩
          · subst is_none
            simp only
            refine (WP.spec_ok _).mpr (Or.inr (Or.inr (Or.inl ⟨serves, free, ?_, rfl⟩)))
            rw [address_is]
            simpa using no_slash
          · subst is_some
            have in_address : Slash ∈ MirrorAddress blk mir ref.val := by
              rw [address_is]
              simpa using has_slash
            have located' : Located (MirrorAddress blk mir ref.val) = some e.Where := by
              rw [address_is]
              simpa using located
            have finish : ∀ digest : Bool, (digest = true ↔ mir.mode = Mode.DigestOnly) →
                MirrorAnswers blocks.val blk mir ask ref.val host.val
                  (.Ok (some { e with by_digest := digest })) := by
              intro digest digest_says
              refine Or.inr (Or.inr (Or.inr ⟨serves, free, { e with by_digest := digest },
                in_address, rfl, located', ?_, ?_, e_creds, digest_says⟩))
              · show e.insecure = true ↔ _
                rw [e_insecure]
                exact insecure_says
              · show e.allow_private = true ↔ _
                rw [e_reach]
                exact reach_says
            simp only
            cases mode
            · exact (WP.spec_ok _).mpr (finish false (by simp [← is_mode]))
            · exact (WP.spec_ok _).mpr (finish true (by simp [← is_mode]))
            · exact (WP.spec_ok _).mpr (finish false (by simp [← is_mode]))
  · have not_serving : does_serve = false := by simpa using serving
    simp only [not_serving, Bool.false_eq_true, ↓reduceIte]
    refine (WP.spec_ok _).mpr (Or.inl ⟨?_, rfl⟩)
    rw [← is_mode]
    intro serves
    exact serving (does_serve_says.mpr serves)

end EndpointCore

