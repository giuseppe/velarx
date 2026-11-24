-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: everything `endpoints` answers, in one statement (`EndpointsAnswer`): for
-- the block chosen for the name, it answers `Blocked` when that block is blocked; else
-- `NoRepository` when the registry's address has no `/` or an asked mirror has none; else the
-- list: the endpoints of the listed mirrors, then the registry's, each with its own flags.  The
-- claims of Spec.lean about the list, the flags, the credentials and the refusals are each a part
-- of this statement (ClaimsOfTheEndpoints.lean and the other `ClaimsOf` files).
-- Why it is needed: `endpoints` is one function; its answer is proved once, line by line, and the
-- claims are read from that.
-- Read before this file: Spec.lean, MirrorsOfTheBlock.lean, RewritesOfNames.lean,
-- EndpointAtAnAddress.lean, SelectChoosesTheBlock.lean.
-- Notation: `step with t as ⟨ x, hx ⟩` runs one line of a Rust function with the theorem `t` and
-- names its result `x` and what is known of it `hx`; `List.Forall₂ R l m` is "`l` and `m` are as
-- long, and `R` holds for the elements at each place".
import EndpointCore.Spec
import EndpointCore.MirrorsOfTheBlock
import EndpointCore.SelectChoosesTheBlock
import EndpointCore.RewritesOfNames
import EndpointCore.EndpointAtAnAddress
import EndpointCore.VectorsAreSlices
import EndpointCore.ChoicesAreUnique

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

/-- What `endpoints` answers for the block `found` chosen for the name `ref`, when the user named
the host `host`. -/
def EndpointsAnswer (blocks : List Block) (found : Option Nat) (ask : Ask) (ref host : Bytes)
    (r : core.result.Result (alloc.vec.Vec Endpoint) Refused) : Prop :=
  (ChosenIsBlocked blocks found ∧ r = .Err .Blocked) ∨
  (¬ ChosenIsBlocked blocks found ∧ Slash ∉ RegistryOf blocks found ref ∧
    r = .Err .NoRepository) ∨
  (¬ ChosenIsBlocked blocks found ∧ Slash ∈ RegistryOf blocks found ref ∧
    AMirrorHasNoRepository blocks found ask ref ∧ r = .Err .NoRepository) ∨
  (¬ ChosenIsBlocked blocks found ∧ Slash ∈ RegistryOf blocks found ref ∧
    ¬ AMirrorHasNoRepository blocks found ask ref ∧
    ∃ es mirrors primary, r = .Ok es ∧ es.val = mirrors ++ [primary] ∧
      Located (RegistryOf blocks found ref) = some primary.Where ∧
      (primary.insecure = true ↔ ChosenIsInsecure blocks found ∨ ask.tls_verify = false) ∧
      (primary.allow_private = true ↔ ChosenAllowsPrivate blocks found) ∧
      (primary.creds = Creds.CommandLine ↔ primary.host.val = Folded host) ∧
      primary.by_digest = false ∧
      List.Forall₂ (IsMirrorEndpoint blocks (ChosenAllowsPrivate blocks found) ask host)
        (ListedMirrors blocks found ask ref) mirrors)

/-- **`endpoints`** answers as `EndpointsAnswer` says, for the block chosen for the name. -/
theorem endpoints_answers (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask)
    (fits : Fits blocks host path) (found : Option Nat)
    (chosen : Chooses blocks.val (NameOf host.val path.val) found) :
    endpoints blocks host path ask ⦃ r =>
      EndpointsAnswer blocks.val found ask (NameOf host.val path.val) host.val r ⦄ := by
  unfold endpoints
  obtain ⟨name_fits, block_fits⟩ := fits
  step as ⟨ slash_slice, is_slash_slice ⟩
  step with join_is_the_two as ⟨ with_slash, is_with_slash ⟩
  have slash_length : slash_slice.length = 1 := by simp [is_slash_slice]
  have with_slash_length : with_slash.length = host.length + 1 := by
    have := congrArg List.length is_with_slash
    simp only [List.length_append] at this
    have : host.val.length = host.length := rfl
    have : slash_slice.val.length = slash_slice.length := rfl
    simp only [alloc.vec.Vec.length]
    omega
  have path_length : path.val.length = path.length := rfl
  step with join_is_the_two with_slash.deref path (by
      simp only [alloc.vec.Vec.length] at with_slash_length
      simp only [Slice.length, deref_keeps_the_bytes]
      omega) as ⟨ full, is_full ⟩
  have full_is : full.val = NameOf host.val path.val := by
    simp [is_full, is_with_slash, is_slash_slice, NameOf, Slash]
  step with select_chooses_the_block as ⟨ chosen', is_chosen' ⟩
  have is_chosen'' : Chooses blocks.val (NameOf host.val path.val) (chosen'.map (·.val)) := by
    rw [← full_is]
    simpa using is_chosen'
  have found_is := a_choice_is_unique _ _ _ _ chosen is_chosen''
  subst found_is
  step with unverified_says_verification_is_off as ⟨ off, off_says ⟩
  step with tail_is_the_end as ⟨ at_block, is_at_block ⟩
  have at_block_is : at_block.deref.val = NameOf host.val path.val := by
    simp [is_at_block, full_is]
  cases chosen' with
  | none =>
    simp only [Option.map_none]
    have registry_is : RegistryOf blocks.val none (NameOf host.val path.val) =
        NameOf host.val path.val := by
      simp [RegistryOf, ChosenBlock]
    have not_blocked : ¬ ChosenIsBlocked blocks.val none := by
      simp [ChosenIsBlocked, ChosenBlock]
    step with at_makes_the_endpoint_of_an_address as ⟨ o, o_says ⟩
    rcases o_says with ⟨no_slash, is_none⟩ | ⟨e, has_slash, is_some, located, e_ins, e_priv,
      e_creds, e_dig⟩
    · subst is_none
      simp only
      refine (WP.spec_ok _).mpr (Or.inr (Or.inl ⟨not_blocked, ?_, rfl⟩))
      rw [registry_is, ← at_block_is]
      exact no_slash
    · subst is_some
      simp only
      step as ⟨ out, is_out ⟩
      refine Or.inr (Or.inr (Or.inr ⟨not_blocked, ?_, ?_, out, [], e, rfl, by simpa using is_out,
        ?_, ?_, ?_, e_creds, e_dig, ?_⟩))
      · rw [registry_is, ← at_block_is]
        exact has_slash
      · simp [AMirrorHasNoRepository, ChosenBlock]
      · rw [registry_is, ← at_block_is]
        exact located
      · simp [ChosenIsInsecure, ChosenBlock, e_ins, off_says]
      · simp [ChosenAllowsPrivate, ChosenBlock, e_priv]
      · simp [ListedMirrors, ChosenBlock]
  | some b =>
    simp only [Option.map_some]
    obtain ⟨block, is_block, _⟩ := is_chosen''.1 b.val (by simp)
    have chosen_block : ChosenBlock blocks.val (some b.val) = some block := by
      simp [ChosenBlock, is_block]
    have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
    have block_in : block ∈ blocks.val := List.mem_of_getElem? is_block
    obtain ⟨location_fits, mirror_fits, few⟩ := block_fits block block_in
    have full_length : full.length = host.length + 1 + path.length := by
      have := congrArg List.length full_is
      simp only [NameOf, List.length_append, List.length_cons] at this
      have : host.val.length = host.length := rfl
      have : path.val.length = path.length := rfl
      simp only [alloc.vec.Vec.length]
      omega
    step as ⟨ blk, is_blk ⟩
    have blk_is : blk = block := by
      have := List.getElem?_eq_getElem inside
      rw [is_block] at this
      simp [is_blk, Option.some.inj this]
    subst blk_is
    by_cases is_blocked : blk.blocked = true
    · simp only [is_blocked, ite_true]
      exact (WP.spec_ok _).mpr (Or.inl ⟨⟨blk, chosen_block, is_blocked⟩, rfl⟩)
    · have not_blocked_flag : blk.blocked = false := by simpa using is_blocked
      simp only [not_blocked_flag, Bool.false_eq_true, ↓reduceIte]
      have not_blocked : ¬ ChosenIsBlocked blocks.val (some b.val) := by
        rintro ⟨block', chosen_block', blocked'⟩
        rw [chosen_block] at chosen_block'
        cases chosen_block'
        exact is_blocked blocked'
      refine WP.spec_bind (Pₘ := fun insecure1 : Bool =>
        insecure1 = true ↔ blk.insecure = true ∨ ask.tls_verify = false) ?_ ?_
      · by_cases is_off : off = true
        · simp only [is_off, ite_true]
          refine (WP.spec_ok _).mpr ?_
          simp [off_says.mp is_off]
        · have not_off : off = false := by simpa using is_off
          simp only [not_off, Bool.false_eq_true, ↓reduceIte]
          refine (WP.spec_ok _).mpr ?_
          have verifying : ¬ ask.tls_verify = false := fun same => is_off (off_says.mpr same)
          simp [verifying]
      · intro insecure1 insecure1_says
        have registered_room : ∀ location, blk.location = some location →
            location.length + full.deref.length ≤ Std.Usize.max := by
          intro location is_location
          have := location_fits location is_location
          simp only [Slice.length, deref_keeps_the_bytes]
          have : full.val.length = full.length := rfl
          omega
        step with registered_is_the_registry_name blocks b full.deref blk is_block
          registered_room as ⟨ at_block1, is_at_block1 ⟩
        have registry_is : RegistryOf blocks.val (some b.val) (NameOf host.val path.val) =
            at_block1.val := by
          simp [RegistryOf, chosen_block, is_at_block1, full_is]
        have registry_deref : at_block1.deref.val = RegistryOf blocks.val (some b.val)
            (NameOf host.val path.val) := by
          rw [registry_is]
          simp
        step with at_makes_the_endpoint_of_an_address as ⟨ o, o_says ⟩
        rcases o_says with ⟨no_slash, is_none⟩ | ⟨primary, has_slash, is_some, located, e_ins,
          e_priv, e_creds, e_dig⟩
        · subst is_none
          simp only
          refine (WP.spec_ok _).mpr (Or.inr (Or.inl ⟨not_blocked, ?_, rfl⟩))
          rw [← registry_deref]
          exact no_slash
        · subst is_some
          simp only
          have primary_at : Located (RegistryOf blocks.val (some b.val)
              (NameOf host.val path.val)) = some primary.Where := by
            rw [← registry_deref]
            exact located
          have mirror_room : ∀ m ∈ blk.mirrors.val, m.location.length + full.length ≤
              Std.Usize.max := by
            intro m m_in
            have := mirror_fits m m_in
            omega
          have chosen_insecure :
              ChosenIsInsecure blocks.val (some b.val) ↔ blk.insecure = true := by
            simp [ChosenIsInsecure, chosen_block]
          have chosen_private : ChosenAllowsPrivate blocks.val (some b.val) ↔
              blk.allow_private = true := by
            simp [ChosenAllowsPrivate, chosen_block]
          have listed_is : ListedMirrors blocks.val (some b.val) ask (NameOf host.val path.val) =
              ListedAmong blocks.val blk ask full.val (RegistryOf blocks.val (some b.val)
                (NameOf host.val path.val)) blk.mirrors.val := by
            simp [ListedMirrors, chosen_block, full_is]
          refine WP.spec_mono (the_mirrors_are_listed_and_the_registry_is_last blocks host ask
            full b _ primary blk _ is_block (by simp [alloc.vec.Vec.len]) mirror_room few
            primary_at) ?_
          rintro r (⟨es, tail, is_ok, es_is, listed, has_repository⟩ |
            ⟨is_err, m, m_in, asked, no_slash⟩)
          · rw [full_is] at has_repository
            rw [full_is] at listed
            refine Or.inr (Or.inr (Or.inr ⟨not_blocked, ?_, ?_, es, tail, primary, is_ok, es_is,
              primary_at, ?_, ?_, e_creds, e_dig, ?_⟩))
            · rw [← registry_deref]
              exact has_slash
            · rintro ⟨block', chosen_block', m, m_in, asked, no_slash⟩
              rw [chosen_block] at chosen_block'
              cases chosen_block'
              exact no_slash (has_repository m m_in asked)
            · rw [e_ins, insecure1_says, chosen_insecure]
            · rw [e_priv, chosen_private]
            · rw [listed_is, full_is]
              exact List.Forall₂.imp (fun p e is_end =>
                a_mirror_endpoint_follows_what_the_listing_block_says _ _ _ chosen_private.symm
                  _ _ _ _ is_end) listed
          · rw [full_is] at asked no_slash
            refine Or.inr (Or.inr (Or.inl ⟨not_blocked, ?_, ⟨blk, chosen_block, m, m_in, asked,
              no_slash⟩, is_err⟩))
            rw [← registry_deref]
            exact has_slash

end EndpointCore
