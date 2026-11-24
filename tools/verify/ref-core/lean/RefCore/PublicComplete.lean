-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the other direction of what the public readers say: `host_error` and
-- `host_ok` find no fault in every host of the grammar, and `prefix_error` and `prefix_ok` in
-- every prefix (a host, or a host, a `/` and a path); with Public.lean, exactly there.
-- Why it is needed: registries.conf and the signature policy call these readers; a reader that
-- refused every name would be of no use, and the claim that says exactly where it accepts rules
-- that out.
-- Read before this file: ParseComplete.lean and Public.lean.
-- Notation: as in Hosts.lean.
import RefCore.ParseComplete
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The piece from the first to the last place of a slice, as the readers of a whole string use it,
is all its bytes. -/
theorem whole_string (s : Slice Std.U8) :
    Piece (Bytes s.val) (0#usize).val s.len.val = Bytes s.val := piece_of_the_whole s

/-- `host_error` has no error exactly for a host of the grammar. -/
theorem host_error_says_exactly (s : Slice Std.U8) :
    host_error s ⦃ r => (r = core.result.Result.Ok () ↔ IsHost (Bytes s.val)) ⦄ := by
  unfold host_error
  dsimp only
  by_cases is_host : IsHost (Bytes s.val)
  · refine WP.spec_bind (host_bad_accepts_every_host s 0#usize s.len (by scalar_tac)
      (by scalar_tac) (by rw [whole_string]; exact is_host)) ?_
    intro o is_none
    subst is_none
    simp only [WP.spec_ok]
    exact ⟨fun _ => is_host, fun _ => trivial⟩
  · step as ⟨ o, o_post ⟩
    rw [piece_of_the_whole] at o_post
    cases o with
    | none => exact absurd (o_post rfl) is_host
    | some at_ => simp [WP.spec_ok, is_host]

/-- `host_ok` says `true` exactly for a host of the grammar. -/
theorem host_ok_says_exactly (s : Slice Std.U8) :
    host_ok s ⦃ r => (r = true ↔ IsHost (Bytes s.val)) ⦄ := by
  unfold host_ok
  dsimp only
  by_cases is_host : IsHost (Bytes s.val)
  · refine WP.spec_bind (host_bad_accepts_every_host s 0#usize s.len (by scalar_tac)
      (by scalar_tac) (by rw [whole_string]; exact is_host)) ?_
    intro o is_none
    subst is_none
    simp only [WP.spec_ok]
    exact ⟨fun _ => is_host, fun _ => rfl⟩
  · step as ⟨ o, o_post ⟩
    rw [piece_of_the_whole] at o_post
    simp only [is_host, iff_false]
    intro is_it
    exact is_host (o_post ((is_none_says o).mp is_it))

/-- `prefix_error` has no error exactly for a host, or a host, a `/` and a path of the grammar. -/
theorem prefix_error_says_exactly (s : Slice Std.U8) (leaves_room : s.length + 8 ≤ Usize.max) :
    prefix_error s ⦃ r => (r = core.result.Result.Ok () ↔ IsPrefix (Bytes s.val)) ⦄ := by
  by_cases is_prefix : IsPrefix (Bytes s.val)
  · unfold prefix_error
    dsimp only
    have len_val : (Slice.len s).val = s.length := by simp
    have zero : (0#usize).val = 0 := rfl
    -- the first `/` ends the host, or there is none
    obtain ⟨host, rest, is_host, cut, kind⟩ : ∃ host rest, IsHost host ∧
        Bytes s.val = host ++ rest ∧ (rest = [] ∨ ∃ path, Path path ∧ rest = 47 :: path) := by
      rcases is_prefix with is_host | ⟨host, path, is_host, is_path, split⟩
      · exact ⟨_, [], is_host, by simp, Or.inl rfl⟩
      · exact ⟨host, 47 :: path, is_host, by rw [split]; simp, Or.inr ⟨path, is_path, rfl⟩⟩
    have no_slash : ∀ x ∈ host, x ≠ 47 := by
      intro x inside is_slash
      have := host_bytes is_host x inside
      unfold IsAlnum IsLower IsDigit at this
      omega
    have width : s.length = host.length + rest.length := by
      have := congrArg List.length cut
      simp only [bytes_length, List.length_append] at this
      exact this
    refine WP.spec_bind (find_goes_to_the_end_of_the_cut s 0#usize s.len 47#u8 host rest
      (by scalar_tac) (by scalar_tac) (by rw [whole_string, cut]) no_slash (by
        rcases kind with empty | ⟨path, _, rest_is⟩
        · exact Or.inl empty
        · exact Or.inr ⟨path, by rw [rest_is]; rfl⟩)) ?_
    intro first first_post
    have host_piece : Piece (Bytes s.val) (0#usize).val first.val = host :=
      piece_of_the_parts s [] host rest 0 first.val (by simpa using cut.symm) rfl
        (by simp only [List.length_nil]; omega)
    refine WP.spec_bind (host_bad_accepts_every_host s 0#usize first (by scalar_tac)
      (by scalar_tac) (by rw [host_piece]; exact is_host)) ?_
    intro o is_none
    subst is_none
    simp only
    split
    · simp only [WP.spec_ok]
      exact ⟨fun _ => is_prefix, fun _ => trivial⟩
    · rename_i not_end
      rcases kind with empty | ⟨path, is_path, rest_is⟩
      · exfalso
        apply not_end
        apply UScalar.eq_of_val_eq
        rw [empty] at width
        simp at width
        scalar_tac
      · have first_lt : first.val < s.length := by
          rw [rest_is] at width; simp at width; scalar_tac
        have path_piece : Piece (Bytes s.val) (first.val + 1) s.length = path :=
          piece_of_the_parts s (host ++ [47]) path [] (first.val + 1) s.length
            (by rw [cut, rest_is]; simp)
            (by simp only [List.length_append, List.length_singleton]; omega)
            (by
              rw [rest_is] at width
              simp only [List.length_append, List.length_cons, List.length_nil] at width ⊢
              omega)
        step as ⟨ start, start_post ⟩
        refine WP.spec_bind (path_bad_accepts_every_path s start s.len (by scalar_tac)
          (by scalar_tac) (by scalar_tac) (by rw [start_post, len_val, path_piece]; exact is_path))
          ?_
        intro o1 is_none1
        subst is_none1
        simp only [WP.spec_ok]
        exact ⟨fun _ => is_prefix, fun _ => trivial⟩
  · refine WP.spec_mono (prefix_error_accepts_only_prefixes s leaves_room) ?_
    intro r is_ok
    exact ⟨fun ok => absurd (is_ok ok) is_prefix, fun yes => absurd yes is_prefix⟩

/-- `prefix_ok` says `true` exactly for a prefix. -/
theorem prefix_ok_says_exactly (s : Slice Std.U8) (leaves_room : s.length + 8 ≤ Usize.max) :
    prefix_ok s ⦃ r => (r = true ↔ IsPrefix (Bytes s.val)) ⦄ := by
  unfold prefix_ok
  step with prefix_error_says_exactly s leaves_room as ⟨ r, r_post ⟩
  cases r with
  | Ok _ => simp only [WP.spec_ok]; exact ⟨fun _ => r_post.mp rfl, fun _ => trivial⟩
  | Err _ => simp [WP.spec_ok] at r_post ⊢; exact r_post

end RefCore
