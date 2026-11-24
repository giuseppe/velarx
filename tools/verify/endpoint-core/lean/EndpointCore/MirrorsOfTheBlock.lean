-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `endpoints` makes of the mirrors of the chosen block: it
-- asks `mirrored` for each one in order, keeps the endpoints of those that are listed (they are
-- not the registry itself), and ends with them followed by the registry; or it ends with the
-- refusal `NoRepository` as soon as a mirror that is asked has no repository.  A push has the
-- registry only.
-- Why it is needed: the claims about the list of endpoints, the flags and the refusals are read
-- from what this loop makes.
-- Read before this file: Spec.lean, MirrorEndpoint.lean, ListedMirrorsOneByOne.lean,
-- MirrorFieldsAreRead.lean.
-- Notation: `List.Forall₂ R l m` is "`l` and `m` are as long, and `R` holds for the elements at
-- each place"; `loop.spec_decr_nat` proves that a loop returns because a number goes down at each
-- turn while a fact (the invariant) is kept by each turn.
import EndpointCore.Spec
import EndpointCore.MirrorEndpoint
import EndpointCore.ListedMirrorsOneByOne
import EndpointCore.PrefixesOfLists
import EndpointCore.VectorsAreSlices
import EndpointCore.ComparingBytes

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

/-- `e` is the endpoint of the mirror `p.1`, listed at the address `p.2`: it is at that address,
with the flags of the mirror (`insecure` by its own entry or by the request, `allow_private` by
the block that lists it, `listing_allows_private`, or by the block chosen for its own address), the
credentials of the command line only for the host that was named, and `by_digest` exactly for a
mirror for digests only. -/
def IsMirrorEndpoint (blocks : List Block) (listing_allows_private : Prop) (ask : Ask)
    (host : Bytes) (p : Mirror × Bytes) (e : Endpoint) : Prop :=
  Slash ∈ p.2 ∧ Located p.2 = some e.Where ∧
    (e.insecure = true ↔ p.1.insecure = true ∨ ask.tls_verify = false) ∧
    (e.allow_private = true ↔ listing_allows_private ∨ AllowsPrivateAt blocks p.2) ∧
    (e.creds = Creds.CommandLine ↔ e.host.val = Folded host) ∧
    (e.by_digest = true ↔ p.1.mode = Mode.DigestOnly)

/-- The block that lists the mirrors says the same whether it is named by the block itself or by
the block chosen: only what it says matters. -/
theorem a_mirror_endpoint_follows_what_the_listing_block_says (blocks : List Block)
    (one other : Prop) (same : one ↔ other) (ask : Ask) (host : Bytes) (p : Mirror × Bytes)
    (e : Endpoint) (is_end : IsMirrorEndpoint blocks one ask host p e) :
    IsMirrorEndpoint blocks other ask host p e := by
  obtain ⟨has_slash, located, insecure, reaches, creds, digest⟩ := is_end
  refine ⟨has_slash, located, insecure, ?_, creds, digest⟩
  rw [reaches, same]

/-- The loop of **`endpoints`**, from the first mirror of the block, with nothing kept: it ends
with the endpoints of the mirrors that are listed, in order, and then the registry (the `primary`,
which is at the address `registry`), or with the refusal `NoRepository` and a mirror that is asked
and has no repository. -/
theorem the_mirrors_are_listed_and_the_registry_is_last (blocks : Slice Block)
    (host : Slice Std.U8) (ask : Ask) (ref : alloc.vec.Vec Std.U8) (b : Std.Usize)
    (count : Std.Usize) (primary : Endpoint) (block : Block) (registry : Bytes)
    (is_block : blocks.val[b.val]? = some block)
    (is_count : count.val = block.mirrors.val.length)
    (room : ∀ m ∈ block.mirrors.val, m.location.length + ref.length ≤ Std.Usize.max)
    (few : block.mirrors.val.length < Std.Usize.max)
    (primary_at : Located registry = some primary.Where) :
    endpoints_loop blocks host ask ref primary (alloc.vec.Vec.new Endpoint) b count 0#usize ⦃ r =>
      (∃ es tail, r = .Ok es ∧ es.val = tail ++ [primary] ∧
        List.Forall₂ (IsMirrorEndpoint blocks.val (block.allow_private = true) ask host.val)
          (ListedAmong blocks.val block ask ref.val registry block.mirrors.val) tail ∧
        ∀ m ∈ block.mirrors.val, Asked blocks.val block ask ref.val m →
          Slash ∈ MirrorAddress block m ref.val) ∨
      (r = .Err .NoRepository ∧ ∃ m ∈ block.mirrors.val, Asked blocks.val block ask ref.val m ∧
        Slash ∉ MirrorAddress block m ref.val) ⦄ := by
  unfold endpoints_loop
  apply loop.spec_decr_nat
    (fun (q : Endpoint × alloc.vec.Vec Endpoint × Std.Usize) =>
      block.mirrors.val.length - q.2.2.val)
    (fun (q : Endpoint × alloc.vec.Vec Endpoint × Std.Usize) =>
      q.1 = primary ∧ q.2.2.val ≤ block.mirrors.val.length ∧
      List.Forall₂ (IsMirrorEndpoint blocks.val (block.allow_private = true) ask host.val)
        (ListedAmong blocks.val block ask ref.val registry (block.mirrors.val.take q.2.2.val))
        q.2.1.val ∧
      ∀ m ∈ block.mirrors.val.take q.2.2.val, Asked blocks.val block ask ref.val m →
        Slash ∈ MirrorAddress block m ref.val)
  · rintro ⟨primary', out, i⟩ ⟨is_primary, inside, kept, has_repository⟩
    simp only at is_primary inside kept has_repository ⊢
    subst is_primary
    unfold endpoints_loop.body
    have kept_length : out.val.length ≤ i.val := by
      have := kept.length_eq
      have := listed_mirrors_are_not_more_than_mirrors blocks.val block ask ref.val registry
        (block.mirrors.val.take i.val)
      simp only [List.length_take] at *
      omega
    by_cases below : i < count
    · have below' : i.val < block.mirrors.val.length := by scalar_tac
      simp only [below, ite_true]
      by_cases pushing : ask.push = true
      · simp only [pushing, ite_true]
        have nothing := a_push_lists_no_mirror blocks.val block ask ref.val registry
          block.mirrors.val pushing
        have nothing_kept := a_push_lists_no_mirror blocks.val block ask ref.val registry
          (block.mirrors.val.take i.val) pushing
        rw [nothing_kept] at kept
        have no_out : out.val = [] :=
          List.length_eq_zero_iff.mp (by simpa using kept.length_eq.symm)
        step as ⟨ out1, is_out1 ⟩
        refine Or.inl ⟨out1, out.val, rfl, by simpa using is_out1, ?_, ?_⟩
        · rw [nothing, no_out]
          exact List.Forall₂.nil
        · intro m _ ⟨no_push, _⟩
          rw [pushing] at no_push
          cases no_push
      · have not_pushing : ask.push = false := by simpa using pushing
        simp only [not_pushing, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨mir, is_mir⟩ : ∃ mir, block.mirrors.val[i.val]? = some mir :=
          ⟨_, List.getElem?_eq_getElem below'⟩
        have mir_room : mir.location.length + ref.deref.length ≤ Std.Usize.max := by
          simpa [Slice.length] using room mir (List.mem_of_getElem? is_mir)
        step with mirrored_answers_for_its_mirror blocks b i ref.deref host ask block mir is_block
          is_mir mir_room as ⟨ answer, answers ⟩
        step as ⟨ cf, is_cf ⟩
        simp only [deref_keeps_the_bytes] at answers
        have grows : block.mirrors.val.take (i.val + 1) =
            block.mirrors.val.take i.val ++ [mir] := by
          rw [take_one_more _ _ below', List.getElem?_eq_getElem below'] at *
          simp [Option.some.inj is_mir]
        have has_repository_grows : (Asked blocks.val block ask ref.val mir →
              Slash ∈ MirrorAddress block mir ref.val) → ∀ next : Std.Usize,
            next.val = i.val + 1 → ∀ m ∈ block.mirrors.val.take next.val,
              Asked blocks.val block ask ref.val m → Slash ∈ MirrorAddress block m ref.val := by
          intro more next is_next m m_in
          rw [is_next, grows] at m_in
          rcases List.mem_append.mp m_in with before | here
          · exact has_repository m before
          · rw [List.mem_singleton.mp here]
            exact more
        have not_asked_so_not_listed : ¬ Asked blocks.val block ask ref.val mir →
            ¬ Listed blocks.val block ask ref.val registry mir := fun not_asked ⟨asked, _⟩ =>
          not_asked asked
        rcases answers with ⟨not_serves, is_answer⟩ | ⟨serves, blocked_here, is_answer⟩ |
          ⟨serves, free, no_slash, is_answer⟩ |
          ⟨serves, free, e, has_slash, is_answer, located, e_ins, e_priv, e_creds, e_dig⟩
        · subst is_answer
          simp only at is_cf
          subst is_cf
          simp only
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, has_repository_grows
            (fun ⟨_, does_serve, _⟩ => absurd does_serve not_serves) next is_next, by scalar_tac⟩
          rw [is_next, grows, a_mirror_that_is_not_listed_changes_nothing _ _ _ _ _ _ _
            (not_asked_so_not_listed fun ⟨_, does_serve, _⟩ => not_serves does_serve)]
          exact kept
        · subst is_answer
          simp only at is_cf
          subst is_cf
          simp only
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, has_repository_grows
            (fun ⟨_, _, not_blocked⟩ => absurd blocked_here not_blocked) next is_next,
            by scalar_tac⟩
          rw [is_next, grows, a_mirror_that_is_not_listed_changes_nothing _ _ _ _ _ _ _
            (not_asked_so_not_listed fun ⟨_, _, not_blocked⟩ => not_blocked blocked_here)]
          exact kept
        · subst is_answer
          simp only at is_cf
          subst is_cf
          simp only
          step with
            core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual_Err.spec
            (alloc.vec.Vec Endpoint) (core.convert.FromSame Refused) Refused.NoRepository
            Refused.NoRepository rfl as ⟨ r1, is_r1 ⟩
          subst is_r1
          exact Or.inr ⟨rfl, mir, List.mem_of_getElem? is_mir, ⟨not_pushing, serves, free⟩,
            no_slash⟩
        · subst is_answer
          simp only at is_cf
          subst is_cf
          simp only
          step with same_is_equality as ⟨ same_host, same_host_says ⟩
          step with same_is_equality as ⟨ same_path, same_path_says ⟩
          have asked : Asked blocks.val block ask ref.val mir := ⟨not_pushing, serves, free⟩
          have is_end : IsMirrorEndpoint blocks.val (block.allow_private = true) ask host.val
              (mir, MirrorAddress block mir ref.val) e :=
            ⟨has_slash, located, e_ins, e_priv, e_creds, e_dig⟩
          by_cases duplicate : same_host = true ∧ same_path = true
          · simp only [duplicate.1, duplicate.2, ite_true]
            step as ⟨ next, is_next ⟩
            refine ⟨by scalar_tac, ?_, has_repository_grows (fun _ => has_slash) next is_next,
              by scalar_tac⟩
            have same_place : e.Where = primary'.Where := by
              have h := same_host_says.mp duplicate.1
              have p := same_path_says.mp duplicate.2
              simp only [deref_keeps_the_bytes] at h p
              simp [Endpoint.Where, h, p]
            have not_listed : ¬ Listed blocks.val block ask ref.val registry mir := by
              rintro ⟨_, differs⟩
              apply differs
              rw [located, primary_at, same_place]
            rw [is_next, grows,
              a_mirror_that_is_not_listed_changes_nothing _ _ _ _ _ _ _ not_listed]
            exact kept
          · have different : ¬ (e.Where = primary'.Where) := by
              intro same_place
              apply duplicate
              have h : e.host.val = primary'.host.val := congrArg Prod.fst same_place
              have p : e.path.val = primary'.path.val := congrArg Prod.snd same_place
              exact ⟨same_host_says.mpr (by simpa using h), same_path_says.mpr (by simpa using p)⟩
            have is_listed : Listed blocks.val block ask ref.val registry mir := by
              refine ⟨asked, ?_⟩
              rw [located, primary_at]
              intro same_located
              exact different (Option.some.inj same_located)
            have push_room : out.val.length < Std.Usize.max := by omega
            have pushed : ∀ v : alloc.vec.Vec Endpoint, v.val = out.val ++ [e] →
                ∀ next : Std.Usize, next.val = i.val + 1 →
                List.Forall₂ (IsMirrorEndpoint blocks.val (block.allow_private = true) ask host.val)
                  (ListedAmong blocks.val block ask ref.val registry
                    (block.mirrors.val.take next.val)) v.val := by
              intro v is_v next is_next
              rw [is_next, grows, a_listed_mirror_is_added _ _ _ _ _ _ _ is_listed, is_v]
              exact List.rel_append kept (List.Forall₂.cons is_end List.Forall₂.nil)
            by_cases host_same : same_host = true
            · have path_differs : ¬ same_path = true :=
                fun path_same => duplicate ⟨host_same, path_same⟩
              have path_false : same_path = false := by simpa using path_differs
              simp only [host_same, path_false, Bool.false_eq_true, ↓reduceIte]
              step as ⟨ v, is_v ⟩
              step as ⟨ next, is_next ⟩
              exact ⟨by scalar_tac, pushed v is_v next is_next,
                has_repository_grows (fun _ => has_slash) next is_next, by scalar_tac⟩
            · have host_false : same_host = false := by simpa using host_same
              simp only [host_false, Bool.false_eq_true, ↓reduceIte]
              step as ⟨ v, is_v ⟩
              step as ⟨ next, is_next ⟩
              exact ⟨by scalar_tac, pushed v is_v next is_next,
                has_repository_grows (fun _ => has_slash) next is_next, by scalar_tac⟩
    · have not_below : ¬ i.val < block.mirrors.val.length := by scalar_tac
      simp only [below, ite_false]
      have room_for_it : out.val.length < Std.Usize.max := by omega
      step as ⟨ out1, is_out1 ⟩
      refine Or.inl ⟨out1, out.val, rfl, by simpa using is_out1, ?_, ?_⟩
      · have at_end : i.val = block.mirrors.val.length := by omega
        rw [at_end, List.take_length] at kept
        exact kept
      · have at_end : i.val = block.mirrors.val.length := by omega
        rw [at_end, List.take_length] at has_repository
        exact has_repository
  · refine ⟨rfl, by simp, ?_, by simp⟩
    simp [ListedAmong]

end EndpointCore
