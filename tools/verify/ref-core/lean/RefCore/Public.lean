-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what two of the small public functions say: `looks_like_host`, and that
-- `prefix_error` and `prefix_ok` find no fault only in a prefix (PublicComplete.lean says the
-- other direction, for these and for `host_error` and `host_ok`).
-- Why it is needed: they are what registries.conf and the signature policy call.
-- Read before this file: Parse.lean.
-- Notation: as in Hosts.lean.
import RefCore.Parse
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The piece from the first to the last place of a slice is all its bytes. -/
theorem piece_of_the_whole (s : Slice Std.U8) :
    Piece (Bytes s.val) 0 (Slice.len s).val = Bytes s.val := by
  have := piece_whole (Bytes s.val)
  simpa using this

/-- `looks_like_host` says `true` exactly for what `LooksLikeHost` describes. -/
theorem looks_like_host_says (first : Slice Std.U8) :
    looks_like_host first ⦃ r => (r = true ↔ LooksLikeHost (Bytes first.val)) ⦄ := by
  unfold looks_like_host
  step as ⟨ r, r_post ⟩
  rw [piece_of_the_whole] at r_post
  exact r_post

/-- `prefix_error` has no error only for a host, or a host, a `/` and a path of the grammar. -/
@[step] theorem prefix_error_accepts_only_prefixes (s : Slice Std.U8)
    (leaves_room : s.length + 8 ≤ Usize.max) :
    prefix_error s ⦃ r => r = core.result.Result.Ok () → IsPrefix (Bytes s.val) ⦄ := by
  unfold prefix_error
  dsimp only
  have len_val : (Slice.len s).val = s.length := by simp
  step as ⟨ first, first_after, first_before, first_none, first_found ⟩
  step as ⟨ o, o_post ⟩
  cases o with
  | some at_ => simp [WP.spec_ok]
  | none =>
    simp only
    split
    · rename_i at_end
      simp only [WP.spec_ok]
      intro _
      have same : first.val = s.length := by
        have : first = Slice.len s := at_end
        rw [this]; exact len_val
      have host := o_post rfl
      rw [same] at host
      have whole := piece_whole (Bytes s.val)
      simp only [bytes_length] at whole
      rw [whole] at host
      exact Or.inl host
    · rename_i not_end
      have below : first.val < s.length := by
        have : first ≠ Slice.len s := not_end
        have : first.val ≠ s.length := fun same => this (UScalar.eq_of_val_eq
            (by rw [same, len_val]))
        scalar_tac
      step as ⟨ start, start_post ⟩
      step as ⟨ o1, o1_post ⟩
      cases o1 with
      | some at_ => simp [WP.spec_ok]
      | none =>
        simp only [WP.spec_ok]
        intro _
        have host := o_post rfl
        have path := o1_post rfl
        rw [start_post, len_val] at path
        have slash := first_found (by scalar_tac)
        refine Or.inr ⟨Piece (Bytes s.val) 0 first, Piece (Bytes s.val) (first.val + 1) s.length,
          host, path, ?_⟩
        have whole := piece_whole (Bytes s.val)
        simp only [bytes_length] at whole
        refine whole.symm.trans ?_
        rw [piece_append _ 0 first.val s.length (Nat.zero_le _) below.le,
          piece_cons _ first.val s.length 47 below slash]
        simp

/-- `prefix_ok` says `true` only for a prefix. -/
theorem prefix_ok_accepts_only_prefixes (s : Slice Std.U8)
    (leaves_room : s.length + 8 ≤ Usize.max) :
    prefix_ok s ⦃ r => r = true → IsPrefix (Bytes s.val) ⦄ := by
  unfold prefix_ok
  step as ⟨ r, r_post ⟩
  cases r with
  | Ok _ => simp only [WP.spec_ok]; exact fun _ => r_post rfl
  | Err _ => simp [WP.spec_ok]

end RefCore
