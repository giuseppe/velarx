-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: three facts about lists that the claims use.  Every element of the second
-- of two lists that are paired by a relation (`List.Forall₂`) has a partner in the first; every
-- mirror that `ListedAmong` lists serves the request; and a name of the right size has a block
-- chosen for it.
-- Why it is needed: the claims about credentials and `by_digest` speak of every endpoint of the
-- list, while the proof of `endpoints` pairs the listed mirrors with their endpoints.
-- Read before this file: Spec.lean, SelectChoosesTheBlock.lean.
-- Notation: `List.Forall₂ R l m` is "`l` and `m` are as long, and `R` holds for the elements at
-- each place".
import EndpointCore.Spec
import EndpointCore.SelectChoosesTheBlock

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

/-- When two lists are paired by a relation, every element of the second has a partner in the
first for which the relation holds. -/
theorem every_element_has_a_partner {α β : Type} (R : α → β → Prop) :
    ∀ (l : List α) (m : List β), List.Forall₂ R l m → ∀ e ∈ m, ∃ p ∈ l, R p e
  | _, _, List.Forall₂.nil, e, e_in => by simp at e_in
  | _, _, List.Forall₂.cons same rest, e, e_in => by
    rcases List.mem_cons.mp e_in with is_first | in_rest
    · exact ⟨_, List.mem_cons_self, by rw [is_first]; exact same⟩
    · obtain ⟨p, p_in, related⟩ := every_element_has_a_partner R _ _ rest e in_rest
      exact ⟨p, List.mem_cons_of_mem _ p_in, related⟩

/-- Every mirror that is listed is asked, so its mode serves the request. -/
theorem a_listed_mirror_serves (blocks : List Block) (block : Block) (ask : Ask)
    (ref registry : Bytes) (ms : List Mirror) (p : Mirror × Bytes)
    (is_listed : p ∈ ListedAmong blocks block ask ref registry ms) :
    Serves p.1.mode ask.has_digest := by
  unfold ListedAmong at is_listed
  obtain ⟨m, m_in, is_p⟩ := List.mem_map.mp is_listed
  have listed := (List.mem_filter.mp m_in).2
  have : Listed blocks block ask ref registry m := by simpa using listed
  rw [← is_p]
  exact this.1.2.1

/-- A host and a path that fit in a `usize` have a block chosen for their name (or none, when no
block governs it): `select` on the name returns it. -/
theorem a_choice_exists (blocks : Slice Block) (host path : Slice Std.U8)
    (fits : Fits blocks host path) :
    ∃ found, Chooses blocks.val (NameOf host.val path.val) found := by
  have small : (NameOf host.val path.val).length ≤ Std.Usize.max := by
    have := fits.1
    simp only [NameOf, List.length_append, List.length_cons]
    have : host.val.length = host.length := rfl
    have : path.val.length = path.length := rfl
    omega
  obtain ⟨found, chosen⟩ := WP.spec_exists
    (select_chooses_the_block blocks (Slice.from (NameOf host.val path.val) small))
  exact ⟨found.map (·.val), by simpa using chosen⟩

end EndpointCore
