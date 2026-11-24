-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `tag_bad` does: when it finds nothing wrong, the bytes are a tag of
-- the grammar (`IsTag`): at most 128 bytes, the first a letter, a digit or `_`, the others also
-- `.` and `-`. It also shows the other direction: `tag_bad` finds nothing wrong in every tag of
-- the grammar.
-- Why it is needed: the tag is the part that comes after the name in a reference.
-- Read before this file: Hosts.lean.
-- Notation: as in Hosts.lean.
import RefCore.Hosts
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The loop of `tag_bad` finds nothing wrong exactly when nothing was wrong before and every byte
is a letter, a digit, `_`, `.` or `-`. -/
@[step] theorem tag_loop_checks_the_bytes (s : Slice Std.U8) (start stop : Std.Usize)
    (bad : Option Std.Usize) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    tag_bad_loop s stop bad start ⦃ r =>
      (r = none ↔ bad = none ∧
        ∀ x ∈ Piece (Bytes s.val) start stop, IsWordByte x ∨ x = 46 ∨ x = 45) ⦄ := by
  unfold tag_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      (q.1 = none ↔ bad = none ∧
        ∀ x ∈ Piece (Bytes s.val) start q.2, IsWordByte x ∨ x = 46 ∨ x = 45))
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold tag_bad_loop.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        step as ⟨ x, x_post ⟩
        step as ⟨ word, word_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_word
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_good_byte _ _ _ _ _ so_far unfound' (Or.inl (word_post.mp is_word))
        · rename_i not_word
          split
          · rename_i not_dot
            split
            · rename_i not_hyphen
              simp only [Std.bind_ok]
              step as ⟨ next, next_post ⟩
              refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
              rw [next_post, snoc]
              exact scan_bad_byte _ _ _ _ _ (fun is_it => is_it.elim
                (fun is_word => not_word (word_post.mpr is_word))
                (fun other => other.elim ((bne_says x 46#u8).mp not_dot)
                  ((bne_says x 45#u8).mp not_hyphen)))
            · rename_i hyphen
              simp only [Std.bind_ok]
              step as ⟨ next, next_post ⟩
              refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
              rw [next_post, snoc]
              have is_hyphen : x.val = 45 := by
                have : ¬ ((x != 45#u8) = true) := hyphen
                simpa [bne_says] using this
              exact scan_good_byte _ _ _ _ _ so_far unfound' (Or.inr (Or.inr is_hyphen))
          · rename_i dot
            simp only [Std.bind_ok]
            step as ⟨ next, next_post ⟩
            refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
            rw [next_post, snoc]
            have is_dot : x.val = 46 := by
              have : ¬ ((x != 46#u8) = true) := dot
              simpa [bne_says] using this
            exact scan_good_byte _ _ _ _ _ so_far unfound' (Or.inr (Or.inl is_dot))
      · rename_i found_one
        simp only [WP.spec_ok]
        exact scan_stops _ _ _ _ _ _ _ after_start before_stop so_far
          (fun is_none => found_one ((is_none_says found).mpr is_none))
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at so_far
      exact so_far
  · exact ⟨by scalar_tac, ordered, by simp [piece_empty]⟩

/-- The longest tag is 128 bytes. -/
theorem max_tag_is_128 : MAX_TAG.val = 128 := by
  simp [global_simps]

/-- `tag_bad` finds nothing wrong only in a tag of the grammar. -/
@[step] theorem tag_bad_accepts_only_tags (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    tag_bad s start stop ⦃ r => (r = none → IsTag (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold tag_bad
  split
  · simp only [Std.bind_ok]
    step as ⟨ r, r_post ⟩
    rename_i is_none
    exact absurd (r_post.mp is_none).1 (by simp)
  · rename_i not_empty
    have below : start.val < stop.val := by
      have : start ≠ stop := not_empty
      scalar_tac
    step as ⟨ first, first_post ⟩
    step as ⟨ word, word_post ⟩
    have first_at := bytes_at s start first (by scalar_tac) first_post
    split
    · rename_i is_word
      step as ⟨ width, width_post ⟩
      split
      · rename_i too_long
        step as ⟨ cut, cut_post ⟩
        step as ⟨ r, r_post ⟩
        rename_i is_none
        exact absurd (r_post.mp is_none).1 (by simp)
      · rename_i short
        simp only [Std.bind_ok]
        step as ⟨ r, r_post ⟩
        rename_i is_none
        have all := r_post.mp is_none
        refine ⟨⟨first.val, ?_, word_post.mp is_word⟩, ?_, all⟩
        · rw [piece_cons _ _ _ first.val below first_at]; rfl
        · rw [piece_length _ _ _ ordered (by simpa using inside)]
          have : ¬ width > MAX_TAG := short
          have := max_tag_is_128
          scalar_tac
    · simp only [Std.bind_ok]
      step as ⟨ r, r_post ⟩
      rename_i is_none
      exact absurd (r_post.mp is_none).1 (by simp)

/-- `tag_bad` finds nothing wrong in every tag of the grammar. -/
theorem tag_bad_accepts_every_tag (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (is_tag : IsTag (Piece (Bytes s.val) start stop)) : tag_bad s start stop ⦃ r => r = none ⦄ := by
  obtain ⟨⟨first, first_is, first_word⟩, short, bytes⟩ := is_tag
  have below : start.val < stop.val := by
    by_contra not_below
    have same : stop.val = start.val := by scalar_tac
    rw [same, piece_empty] at first_is
    simp at first_is
  have first_at := piece_head _ _ _ _ below first_is
  have width : (Piece (Bytes s.val) start stop).length = stop.val - start.val :=
    piece_length _ _ _ ordered (by simpa using inside)
  unfold tag_bad
  split
  · rename_i empty
    have : start.val = stop.val := by rw [empty]
    omega
  · refine WP.spec_bind (Pₘ := fun bad => bad = none) ?_ ?_
    · step as ⟨ x, x_post ⟩
      step as ⟨ word, word_post ⟩
      have x_at := bytes_at s start x (by scalar_tac) x_post
      rw [first_at] at x_at
      have x_is : x.val = first := (Option.some.inj x_at).symm
      split
      · step as ⟨ taken, taken_post ⟩
        split
        · rename_i too_long
          have : ¬ taken ≤ MAX_TAG := by simpa using too_long
          have := max_tag_is_128
          scalar_tac
        · simp [WP.spec_ok]
      · rename_i not_word
        exact absurd (word_post.mpr (by rw [x_is]; exact first_word)) not_word
    · intro bad is_none
      step as ⟨ r, r_post ⟩
      exact r_post.mpr ⟨is_none, bytes⟩

end RefCore
