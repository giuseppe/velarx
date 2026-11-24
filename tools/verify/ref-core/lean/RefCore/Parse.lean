-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that what `parse` accepts is in the grammar: it follows `parse` line by
-- line, from the `@` to the check that the string is not the id of an image, and at the end uses
-- Reading.lean.
-- Why it is needed: this is the claim that matters for security: what reaches a URL as a host or a
-- path has been checked against the grammar.
-- Read before this file: Reading.lean.
-- Notation: `refine WP.spec_bind (lemma) ?_` goes through one line `let x ← m` of a Rust function:
-- `lemma` says what `m` returns, the rest is shown for each result that fits.
import RefCore.Reading
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The error of the digest that `parse` computes is none only for a digest of the grammar, when
there is one. -/
theorem digest_error_says (s : Slice Std.U8) (at_ : Std.Usize) (_ordered : at_.val ≤ s.length)
    (_small : s.length ≤ 1024) :
    (if at_ < s.len then do
        let i ← at_ + 1#usize
        digest_bad s i s.len
      else ok none) ⦃ e => e = none →
        (at_.val < s.length → ∃ i : Std.Usize, i.val = at_.val + 1 ∧
          IsDigest (Piece (Bytes s.val) i s.len)) ⦄ := by
  split
  · rename_i has_digest
    step as ⟨ i, i_post ⟩
    step as ⟨ e, e_post ⟩
    rename_i is_none _
    exact ⟨i, i_post, e_post is_none⟩
  · rename_i no_digest
    simp only [WP.spec_ok]
    intro _ below
    exact absurd (by scalar_tac) no_digest

/-- The digest that `parse` computes is none when there is no `@`, and else the bytes after it. -/
theorem digest_value_says (s : Slice Std.U8) (at_ : Std.Usize) (_ordered : at_.val ≤ s.length)
    (_small : s.length ≤ 1024) :
    (if at_ < s.len then do
        let i ← at_ + 1#usize
        ok (some (i, s.len))
      else ok none) ⦃ d => (d = none ∧ at_.val = s.length) ∨
        (at_.val < s.length ∧ ∃ i : Std.Usize, i.val = at_.val + 1 ∧ d = some (i, s.len)) ⦄ := by
  split
  · rename_i has_digest
    step as ⟨ i, i_post ⟩
    exact Or.inr ⟨by scalar_tac, i, i_post, rfl⟩
  · rename_i no_digest
    simp only [WP.spec_ok]
    exact Or.inl ⟨by simp, by scalar_tac⟩

/-- The error of the tag that `parse` computes is none only for a tag of the grammar, when there is
one. -/
theorem tag_error_says (s : Slice Std.U8) (name_end at_ : Std.Usize)
    (_ordered : name_end.val ≤ at_.val) (inside : at_.val ≤ s.length) (_small : s.length ≤ 1024) :
    (if name_end < at_ then do
        let i ← name_end + 1#usize
        tag_bad s i at_
      else ok none) ⦃ e => e = none →
        (name_end.val < at_.val → ∃ i : Std.Usize, i.val = name_end.val + 1 ∧
          IsTag (Piece (Bytes s.val) i at_)) ⦄ := by
  split
  · rename_i has_tag
    step as ⟨ i, i_post ⟩
    step as ⟨ e, e_post ⟩
    rename_i is_none _
    exact ⟨i, i_post, e_post is_none⟩
  · rename_i no_tag
    simp only [WP.spec_ok]
    intro _ below
    exact absurd (by scalar_tac) no_tag

/-- The tag that `parse` computes is none when the name ends at the digest, and else the bytes after
the colon. -/
theorem tag_value_says (s : Slice Std.U8) (name_end at_ : Std.Usize)
    (_ordered : name_end.val ≤ at_.val) (inside : at_.val ≤ s.length) (_small : s.length ≤ 1024) :
    (if name_end < at_ then do
        let i ← name_end + 1#usize
        ok (some (i, at_))
      else ok none) ⦃ t => (t = none ∧ name_end.val = at_.val) ∨
        (name_end.val < at_.val ∧ ∃ i : Std.Usize, i.val = name_end.val + 1 ∧ t = some
            (i, at_)) ⦄ := by
  split
  · rename_i has_tag
    step as ⟨ i, i_post ⟩
    exact Or.inr ⟨by scalar_tac, i, i_post, rfl⟩
  · rename_i no_tag
    simp only [WP.spec_ok]
    exact Or.inl ⟨by simp, by scalar_tac⟩

/-- The place after the last `/` of what comes before the digest is not after the digest. -/
theorem last_slash_says (at_ : Std.Usize) (o : Option Std.Usize)
    (before : ∀ k, o = some k → k.val < at_.val) (small : at_.val ≤ 1024) :
    (match o with
      | none => ok 0#usize
      | some slash => slash + 1#usize) ⦃ last => last.val ≤ at_.val ⦄ := by
  cases o with
  | none => simp [WP.spec_ok]
  | some k =>
    have below := before k rfl
    simp only
    step as ⟨ next, next_post ⟩
    scalar_tac

/-- The end of the host that `parse` computes is 0 or the place of the first `/`: 0 when there is no
`/` or what is before it does not look like a host. -/
theorem host_end_says (s : Slice Std.U8) (first name_end : Std.Usize)
    (inside : name_end.val ≤ s.length) (first_before : first.val ≤ name_end.val)
    (first_none : ∀ x ∈ Piece (Bytes s.val) 0 first, x ≠ 47)
    (first_found : first.val < name_end.val → (Bytes s.val)[first.val]? = some 47) :
    (if first < name_end then do
        let b ← host_like s 0#usize first
        if b = true then ok first else ok 0#usize
      else ok 0#usize) ⦃ h =>
      (h.val = 0 ∧ (47 ∈ Piece (Bytes s.val) 0 name_end →
        ¬ LooksLikeHost ((Piece (Bytes s.val) 0 name_end).takeWhile (· ≠ 47)))) ∨
      (0 < h.val ∧ h.val < name_end.val ∧ (Bytes s.val)[h.val]? = some 47 ∧
        LooksLikeHost (Piece (Bytes s.val) 0 h)) ⦄ := by
  split
  · rename_i has_slash
    step as ⟨ like, like_post ⟩
    split
    · rename_i looks
      simp only [WP.spec_ok]
      have looks' := like_post.mp looks
      have positive : 0 < first.val := by
        by_contra zero
        have : first.val = 0 := by omega
        rw [this, piece_empty] at looks'
        simp [LooksLikeHost, Ascii] at looks'
      exact Or.inr ⟨positive, has_slash, first_found has_slash, looks'⟩
    · rename_i not_like
      simp only [WP.spec_ok]
      refine Or.inl ⟨rfl, fun _ => ?_⟩
      have first_at := first_found has_slash
      have cut : Piece (Bytes s.val) 0 name_end = Piece (Bytes s.val) 0 first ++
          47 :: Piece (Bytes s.val) (first.val + 1) name_end := by
        rw [piece_append _ 0 first name_end (Nat.zero_le _) first_before,
          piece_cons _ first name_end 47 has_slash first_at]
      rw [cut, take_before_the_byte _ _ 47 first_none]
      exact fun h => not_like (like_post.mpr h)
  · rename_i no_slash
    simp only [WP.spec_ok]
    refine Or.inl ⟨rfl, fun slash_in => ?_⟩
    have same : first.val = name_end.val := by scalar_tac
    rw [← same] at slash_in
    exact absurd rfl (first_none 47 slash_in)

/-- The error of the host that `parse` computes is none only for a host of the grammar, when there
is one. -/
theorem host_error_says (s : Slice Std.U8) (host_end : Std.Usize)
    (inside : host_end.val ≤ s.length) :
    (if host_end > 0#usize then host_bad s 0#usize host_end else ok none) ⦃ e => e = none →
      (0 < host_end.val → IsHost (Piece (Bytes s.val) 0 host_end)) ⦄ := by
  split
  · rename_i has_host
    step as ⟨ e, e_post ⟩
    rename_i is_none _
    exact e_post is_none
  · rename_i no_host
    simp only [WP.spec_ok]
    intro _ positive
    exact absurd (by scalar_tac) no_host

/-- What `parse` accepts is in the grammar, the spans cut the string into its parts, and the readers
found what `Found` says. -/
theorem parse_accepts_only_the_grammar (s : Slice Std.U8) :
    parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
      ((spans.Reading s).InGrammar ∧ (spans.Reading s).Text = Bytes s.val) ∧
        ∃ at_, Found s spans at_ ⦄ := by
  unfold parse
  dsimp only
  split
  · simp [WP.spec_ok]
  · rename_i not_empty
    split
    · simp [WP.spec_ok]
    · rename_i not_long
      have small : s.length ≤ 1024 := by
        have : ¬ Slice.len s > MAX_INPUT := not_long
        simp [global_simps] at this
        scalar_tac
      have len_val : s.len.val = s.length := by simp
      step as ⟨ at_, at_after, at_before, at_none, at_found ⟩
      refine WP.spec_bind (digest_error_says s at_ (by scalar_tac) small) ?_
      intro digest_error digest_ok
      cases digest_error with
      | some bad => simp [WP.spec_ok]
      | none =>
        simp only
        refine WP.spec_bind (digest_value_says s at_ (by scalar_tac) small) ?_
        intro digest digest_says
        step as ⟨ o, o_none, o_some ⟩
        refine WP.spec_bind (last_slash_says at_ o (fun k is_k => (o_some k is_k).2.1)
          (by scalar_tac)) ?_
        intro last last_le
        step as ⟨ name_end, ne_after, ne_before, ne_none, ne_found ⟩
        refine WP.spec_bind (tag_error_says s name_end at_ (by scalar_tac) (by scalar_tac) small) ?_
        intro tag_error tag_ok
        cases tag_error with
        | some bad => simp [WP.spec_ok]
        | none =>
          simp only
          refine WP.spec_bind (tag_value_says s name_end at_ (by scalar_tac)
              (by scalar_tac) small) ?_
          intro tag tag_says
          step as ⟨ first, first_after, first_before, first_none, first_found ⟩
          refine WP.spec_bind (host_end_says s first name_end (by scalar_tac) (by scalar_tac)
            first_none first_found) ?_
          intro host_end host_says
          have host_bound : host_end.val ≤ s.length := by
            rcases host_says with ⟨zero, _⟩ | ⟨_, below, _⟩ <;> scalar_tac
          have path_after : PathStart host_end.val ≤ name_end.val := by
            unfold PathStart
            rcases host_says with ⟨zero, _⟩ | ⟨positive, below, _⟩
            · simp [zero]
            · have : host_end.val ≠ 0 := by omega
              simp [this]; omega
          refine WP.spec_bind (host_error_says s host_end host_bound) ?_
          intro host_error host_ok
          cases host_error with
          | some bad => simp [WP.spec_ok]
          | none =>
            simp only
            step as ⟨ ps, ps_post ⟩
            step as ⟨ o1, o1_post ⟩
            cases o1 with
            | some bad => simp [WP.spec_ok]
            | none =>
              simp only
              step as ⟨ length, length_post ⟩
              split
              · simp [WP.spec_ok]
              · rename_i fits
                step as ⟨ is_id_r, is_id_post ⟩
                split
                · simp [WP.spec_ok]
                · rename_i not_id
                  simp only [WP.spec_ok]
                  intro spans is_ok
                  simp only [core.result.Result.Ok.injEq] at is_ok
                  subst is_ok
                  have fits' : length.val ≤ 255 := by
                    have : ¬ length > MAX_NAME := fits
                    simp [global_simps] at this
                    scalar_tac
                  have found : Found s (Spans.mk host_end name_end tag digest) at_ := by
                    refine ⟨small, ⟨by scalar_tac, by scalar_tac⟩, ?_, ?_, ?_, ?_⟩
                    · rcases host_says with ⟨zero, _⟩ | ⟨positive, below, slash, looks⟩
                      · exact Or.inl zero
                      · exact Or.inr ⟨positive, below, slash, host_ok rfl positive, looks⟩
                    · intro zero slash_in
                      rcases host_says with ⟨_, first_component⟩ | ⟨positive, _⟩
                      · exact first_component slash_in
                      · exact absurd (show host_end.val = 0 from zero) (by omega)
                    · rcases tag_says with ⟨none_, same⟩ | ⟨below, i, i_post, some_⟩
                      · exact Or.inl ⟨none_, same⟩
                      · obtain ⟨i', i'_post, good⟩ := tag_ok rfl below
                        have same_i : i' = i := UScalar.eq_of_val_eq (by rw [i_post, i'_post])
                        subst same_i
                        exact Or.inr ⟨below, ne_found below, i', i_post, some_, good⟩
                    · rcases digest_says with ⟨none_, same⟩ | ⟨below, i, i_post, some_⟩
                      · exact Or.inl ⟨none_, same⟩
                      · obtain ⟨i', i'_post, good⟩ := digest_ok rfl below
                        have same_i : i' = i := UScalar.eq_of_val_eq (by rw [i_post, i'_post])
                        subst same_i
                        exact Or.inr ⟨below, at_found (by scalar_tac), i', i_post, some_, good⟩
                  have path := o1_post rfl
                  rw [ps_post] at path
                  have not_id' : ¬ (name_end.val = 64 ∧ host_end.val = 0 ∧ tag = none
                      ∧ digest = none ∧
                      ∀ x ∈ Piece (Bytes s.val) 0 name_end, IsHex x) :=
                    fun is_it => not_id ((is_id_post).mpr is_it)
                  refine ⟨found_is_in_the_grammar s _ at_ found path ?_ not_id',
                    found_cuts_the_string s _ at_ found, at_, found⟩
                  rw [length_post] at fits'
                  exact fits'

end RefCore
