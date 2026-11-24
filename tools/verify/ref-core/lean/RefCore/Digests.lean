-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `digest_bad` does: when it finds nothing wrong, the bytes are a
-- digest of the grammar (`IsDigest`): `sha256:` and 64 lower-case hex digits, or `sha384:` and 96,
-- or `sha512:` and 128. It also shows the other direction: `digest_bad` finds nothing wrong in
-- every digest of the grammar.
-- Why it is needed: a digest names the content of an image, so what is not exactly one must be
-- refused.
-- Read before this file: Tags.lean.
-- Notation: `Ascii "sha256:"` is the list of the numbers of the bytes of that text.
import RefCore.Tags
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The loop of `digest_bad` finds nothing wrong exactly when nothing was wrong before and every
byte from the start to the end is a hex digit. -/
@[step] theorem digest_loop_checks_the_digits (s : Slice Std.U8) (start stop : Std.Usize)
    (bad : Option Std.Usize) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    digest_bad_loop s stop bad start ⦃ r =>
      (r = none ↔ bad = none ∧ ∀ x ∈ Piece (Bytes s.val) start stop, IsHex x) ⦄ := by
  unfold digest_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      (q.1 = none ↔ bad = none ∧ ∀ x ∈ Piece (Bytes s.val) start q.2, IsHex x))
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold digest_bad_loop.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        step as ⟨ x, x_post ⟩
        step as ⟨ hex, hex_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_hex
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_good_byte _ _ _ _ _ so_far unfound' (hex_post.mp is_hex)
        · rename_i not_hex
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_bad_byte _ _ _ _ _ (fun is_it => not_hex (hex_post.mpr is_it))
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


/-- A loop that begins with a bad byte found ends with one, even when it begins past the end. -/
theorem digest_loop_keeps_the_mark (s : Slice Std.U8) (start stop : Std.Usize)
    (place : Std.Usize) : digest_bad_loop s stop (some place) start ⦃ r => r ≠ none ⦄ := by
  unfold digest_bad_loop
  apply loop.spec_decr_nat (fun (_ : Option Std.Usize × Std.Usize) => 0)
    (fun (q : Option Std.Usize × Std.Usize) => q.1 ≠ none)
  · rintro ⟨found, i⟩ marked
    simp only at marked
    unfold digest_bad_loop.body
    dsimp only
    split
    · have not_none : core.option.Option.is_none found ≠ true := fun is_none =>
        marked ((is_none_says found).mp is_none)
      simp only [not_none, Bool.false_eq_true, ite_false, WP.spec_ok]
      exact marked
    · simpa using marked
  · simp

/-- What follows the algorithm of a digest: when the algorithm was found (`hex` is the number of
hex digits it asks for), the digits are checked, and the string is a digest. -/
theorem digest_after_the_algorithm (s : Slice Std.U8) (start stop width hex : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max)
    (width_is : width.val = stop.val - start.val)
    (algorithm : hex = 0#usize ∨ ∃ text, 7 ≤ width.val ∧
      Piece (Bytes s.val) start (start.val + 7) = Ascii text ∧
      ((text = "sha256:" ∧ hex.val = 64) ∨ (text = "sha384:" ∧ hex.val = 96) ∨
        (text = "sha512:" ∧ hex.val = 128))) :
    (do
      let bad ← if hex = 0#usize then ok (some start)
        else do
          let i1 ← 7#usize + hex
          if (width != i1) = true then ok (some stop) else ok none
      let i1 ← start + 7#usize
      digest_bad_loop s stop bad i1) ⦃ r => (r = none → IsDigest (Piece
          (Bytes s.val) start stop)) ⦄ := by
  split
  · rename_i no_algorithm
    simp only [Std.bind_ok]
    step as ⟨ past, past_post ⟩
    step with digest_loop_keeps_the_mark s past stop start as ⟨ r, r_post ⟩
    rename_i is_none
    exact absurd is_none r_post
  · rename_i has_algorithm
    obtain ⟨text, seven, prefix_is, kinds⟩ := algorithm.resolve_left has_algorithm
    have hex_small : hex.val ≤ 128 := by rcases kinds with ⟨_, h⟩ | ⟨_, h⟩ | ⟨_, h⟩ <;> omega
    step as ⟨ total, total_post ⟩
    split
    · rename_i wrong_width
      simp only [Std.bind_ok]
      step as ⟨ past, past_post ⟩
      step with digest_loop_keeps_the_mark s past stop stop as ⟨ r, r_post ⟩
      rename_i is_none
      exact absurd is_none r_post
    · rename_i right_width
      have width_is_total : width.val = total.val := by
        have : ¬ (width != total) = true := right_width
        simpa [bne_says] using this
      simp only [Std.bind_ok]
      step as ⟨ digits, digits_post ⟩
      step as ⟨ r, r_post ⟩
      rename_i is_none
      have all := r_post.mp is_none
      rw [digits_post] at all
      have seven_in : start.val + 7 ≤ stop.val := by scalar_tac
      have seven_in' : start.val ≤ start.val + 7 ∧ start.val + 7 ≤ stop.val := ⟨by omega, seven_in⟩
      refine ⟨text, hex.val, Piece (Bytes s.val) (start.val + 7) stop.val, ?_, all, ?_, kinds⟩
      · rw [piece_append _ start (start.val + 7) stop seven_in'.1 seven_in'.2, prefix_is]
      · rw [piece_length _ _ _ seven_in (by simpa using inside)]
        scalar_tac

/-- `digest_bad` finds nothing wrong only in a digest of the grammar. -/
@[step] theorem digest_bad_accepts_only_digests (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max) :
    digest_bad s start stop ⦃ r => (r = none → IsDigest (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold digest_bad
  step as ⟨ width, width_post ⟩
  refine WP.spec_bind (Pₘ := fun hex => hex = 0#usize ∨ ∃ text, 7 ≤ width.val ∧
      Piece (Bytes s.val) start (start.val + 7) = Ascii text ∧
      ((text = "sha256:" ∧ hex.val = 64) ∨ (text = "sha384:" ∧ hex.val = 96) ∨
        (text = "sha512:" ∧ hex.val = 128))) ?_ ?_
  · split
    · simp [WP.spec_ok]
    · rename_i enough
      have seven : 7 ≤ width.val := by
        have : ¬ width < 7#usize := enough
        scalar_tac
      simp only [lift, Std.bind_ok]
      step as ⟨ past, past_post ⟩
      step as ⟨ is_sha256, is_sha256_post ⟩
      split
      · rename_i found
        have lit := is_sha256_post.mp found
        simp only [WP.spec_ok]
        refine Or.inr ⟨"sha256:", seven, ?_, Or.inl ⟨rfl, rfl⟩⟩
        rw [← past_post]
        exact lit.trans (by rfl)
      · rename_i not_sha256
        step as ⟨ is_sha384, is_sha384_post ⟩
        split
        · rename_i found
          have lit := is_sha384_post.mp found
          simp only [WP.spec_ok]
          refine Or.inr ⟨"sha384:", seven, ?_, Or.inr (Or.inl ⟨rfl, rfl⟩)⟩
          rw [← past_post]
          exact lit.trans (by rfl)
        · rename_i not_sha384
          step as ⟨ is_sha512, is_sha512_post ⟩
          split
          · rename_i found
            have lit := is_sha512_post.mp found
            simp only [WP.spec_ok]
            refine Or.inr ⟨"sha512:", seven, ?_, Or.inr (Or.inr ⟨rfl, rfl⟩)⟩
            rw [← past_post]
            exact lit.trans (by rfl)
          · simp [WP.spec_ok]
  · intro hex algorithm
    exact digest_after_the_algorithm s start stop width hex ordered inside room width_post algorithm

/-- The number of hex digits that the algorithm of a digest asks for. -/
def DigestCount (algorithm : String) : Nat :=
  if algorithm = "sha256:" then 64 else if algorithm = "sha384:" then 96 else 128

/-- `digest_bad` finds nothing wrong in every digest of the grammar. -/
theorem digest_bad_accepts_every_digest (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (is_digest : IsDigest (Piece (Bytes s.val) start stop)) :
    digest_bad s start stop ⦃ r => r = none ⦄ := by
  obtain ⟨algorithm, count, hex, split, hex_digits, hex_count, kinds⟩ := is_digest
  have seven : (Ascii algorithm).length = 7 := by
    rcases kinds with ⟨rfl, _⟩ | ⟨rfl, _⟩ | ⟨rfl, _⟩ <;> rfl
  have width : stop.val - start.val = 7 + count := by
    have := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
    rw [split] at this
    simp only [List.length_append, seven, hex_count] at this
    omega
  have count_small : count ≤ 128 := by rcases kinds with ⟨_, h⟩ | ⟨_, h⟩ | ⟨_, h⟩ <;> omega
  have first_seven : Piece (Bytes s.val) start (start.val + 7) = Ascii algorithm := by
    have := piece_take (Bytes s.val) start stop (start.val + 7) (by omega) (by omega)
    rw [split, show start.val + 7 - start.val = 7 by omega, ← seven, List.take_left, seven] at this
    exact this.symm
  have the_digits : Piece (Bytes s.val) (start.val + 7) stop = hex := by
    have := piece_append (Bytes s.val) start (start.val + 7) stop (by omega) (by omega)
    rw [split, first_seven] at this
    exact (List.append_cancel_left this).symm
  unfold digest_bad
  step as ⟨ i, i_post ⟩
  refine WP.spec_bind (Pₘ := fun hexes => hexes.val = count) ?_ ?_
  · split
    · rename_i short
      have : i.val < 7 := by scalar_tac
      omega
    · simp only [lift, Std.bind_ok]
      step as ⟨ past, past_post ⟩
      step as ⟨ is_sha256, is_sha256_post ⟩
      split
      · rename_i found
        simp only [WP.spec_ok]
        rcases kinds with ⟨rfl, c⟩ | ⟨rfl, c⟩ | ⟨rfl, c⟩
        · exact c.symm ▸ rfl
        · have := is_sha256_post.mp found
          rw [past_post, first_seven] at this
          exact absurd this (by decide)
        · have := is_sha256_post.mp found
          rw [past_post, first_seven] at this
          exact absurd this (by decide)
      · rename_i not_sha256
        step as ⟨ is_sha384, is_sha384_post ⟩
        split
        · rename_i found
          simp only [WP.spec_ok]
          rcases kinds with ⟨rfl, c⟩ | ⟨rfl, c⟩ | ⟨rfl, c⟩
          · exact absurd (is_sha256_post.mpr (by rw [past_post, first_seven]; rfl)) not_sha256
          · exact c.symm ▸ rfl
          · have := is_sha384_post.mp found
            rw [past_post, first_seven] at this
            exact absurd this (by decide)
        · rename_i not_sha384
          step as ⟨ is_sha512, is_sha512_post ⟩
          split
          · rename_i found
            simp only [WP.spec_ok]
            rcases kinds with ⟨rfl, c⟩ | ⟨rfl, c⟩ | ⟨rfl, c⟩
            · exact absurd (is_sha256_post.mpr (by rw [past_post, first_seven]; rfl)) not_sha256
            · exact absurd (is_sha384_post.mpr (by rw [past_post, first_seven]; rfl)) not_sha384
            · exact c.symm ▸ rfl
          · rename_i not_sha512
            exfalso
            rcases kinds with ⟨rfl, c⟩ | ⟨rfl, c⟩ | ⟨rfl, c⟩
            · exact not_sha256 (is_sha256_post.mpr (by rw [past_post, first_seven]; rfl))
            · exact not_sha384 (is_sha384_post.mpr (by rw [past_post, first_seven]; rfl))
            · exact not_sha512 (is_sha512_post.mpr (by rw [past_post, first_seven]; rfl))
  · intro hexes hexes_is
    have positive : hexes ≠ 0#usize := by
      intro zero
      rw [zero] at hexes_is
      rcases kinds with ⟨_, c⟩ | ⟨_, c⟩ | ⟨_, c⟩ <;> simp at hexes_is <;> omega
    simp only [positive, ↓reduceIte]
    step as ⟨ total, total_post ⟩
    have counted : ¬ (i != total) = true := by
      have same : i = total := UScalar.eq_of_val_eq (by scalar_tac)
      simp [same]
    simp only [counted, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
    step as ⟨ digits, digits_post ⟩
    step as ⟨ r, r_post ⟩
    rw [digits_post, the_digits] at r_post
    exact r_post.mpr hex_digits

end RefCore
